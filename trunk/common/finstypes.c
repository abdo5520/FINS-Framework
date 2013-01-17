/*
 * finstypes.c
 *
 *  Created on: Jul 21, 2011
 *      Author: dell-kevin
 */

#include "finstypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>

uint32_t control_serial_num = 0;
sem_t control_serial_sem;

void *secure_malloc_full(const char *file, const char *func, int line, uint32_t len) {
	void *buf = malloc(len);
	if (buf == NULL) {
#ifdef ERROR
		printf("ERROR(%s, %s, %d):alloc error: len=%u\n", __FILE__, __FUNCTION__, __LINE__, len);
		fflush(stdout);
#endif
		exit(-1);
	}
	return buf;
}

void secure_sem_wait_full(const char *file, const char *func, int line, sem_t *sem) {
	int ret;
	if ((ret = sem_wait(sem))) {
#ifdef ERROR
		printf("ERROR(%s, %s, %d):sem wait prob: sem=%p, ret=%d\n", __FILE__, __FUNCTION__, __LINE__, sem, ret);
		fflush(stdout);
#endif
		exit(-1);
	}
}

void secure_metadata_readFromElement_full(const char *file, const char *func, int line, metadata *params, const char *target, void *value) {
	if (metadata_readFromElement(params, target, value) == META_FALSE) {
#ifdef ERROR
		printf("ERROR(%s, %s, %d):metadata read: meta=%p, target='%s', value=%p\n", __FILE__, __FUNCTION__, __LINE__, params, target, value);
		fflush(stdout);
#endif
		exit(-1);
	}
}

void secure_metadata_writeToElement_full(const char *file, const char *func, int line, metadata *params, char *target, void *value, int type) {
	if (metadata_writeToElement(params, target, value, type) == META_FALSE) {
#ifdef ERROR
		printf("ERROR(%s, %s, %d):metadata write: meta=%p, target='%s', value=%p, type=%d\n", __FILE__, __FUNCTION__, __LINE__, params, target, value, type);
		fflush(stdout);
#endif
		exit(-1);
	}
}

uint32_t gen_control_serial_num(void) {
	uint32_t num;

	//TODO replace this with a random number generator
	secure_sem_wait(&control_serial_sem);
	num = ++control_serial_num;
	sem_post(&control_serial_sem);

	return num;
}

struct finsFrame * buildFinsFrame(void) { //TODO replace with createFinsFrame() or just remove

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));

	PRINT_DEBUG("2.1");
	int linkvalue = 80211;
	char linkname[] = "linklayer";
	unsigned char fakeDatav[] = "loloa77a7";
	unsigned char *fakeData = fakeDatav;

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));

	//metadata *params;
	PRINT_DEBUG("2.2");
	metadata_create(params);
	PRINT_DEBUG("2.3");
	metadata_addElement(params, linkname, META_TYPE_INT32);
	PRINT_DEBUG("2.4");
	metadata_writeToElement(params, linkname, &linkvalue, META_TYPE_INT32);
	PRINT_DEBUG("2.5");
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = (unsigned char) 200;
	ff->destinationID.next = NULL;

	ff->dataFrame.directionFlag = UP;
	ff->metaData = params;
	ff->dataFrame.pdu = fakeData;
	ff->dataFrame.pduLength = 10;

	return ff;
}

/**@brief prints the contents of a fins frame whether data or control type
 * @param fins_in the pointer to the fins frame
 * */
void print_finsFrame(struct finsFrame *ff) {

	struct destinationList *dest;

	PRINT_DEBUG("Printing FINS frame:");

	dest = &(ff->destinationID);

	while (dest != NULL) {
		PRINT_DEBUG("Destination id %d", dest->id);
		dest = dest->next;
	}

	if (ff->dataOrCtrl == DATA) {
		PRINT_DEBUG("Data fins %d", ff->dataOrCtrl);
		PRINT_DEBUG("Direction flag %d", ff->dataFrame.directionFlag);
		//PRINT_DEBUG("Meta data (first element) 0x%x", fins_in->metaData);
		PRINT_DEBUG("PDU size (bytes) %d", ff->dataFrame.pduLength);
		int i = 0;
		while (i < ff->dataFrame.pduLength) {
			PRINT_DEBUG("%d", ff->dataFrame.pdu[i]);
			i++;

		}
		//######################
#ifdef DEBUG
		char *temp = (char *) secure_malloc(ff->dataFrame.pduLength + 1);
		memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
		temp[ff->dataFrame.pduLength] = '\0';
		PRINT_DEBUG("pdu=%s", temp);
		free(temp);
#endif
		//######################
	} else if (ff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("Control fins %d", ff->dataOrCtrl);
		PRINT_DEBUG("Opcode %d", ff->ctrlFrame.opcode);
		PRINT_DEBUG("Parameter ID %d", ff->ctrlFrame.param_id);
		PRINT_DEBUG("Parameter Value %d", *(int *) (ff->ctrlFrame.data));
		//		PRINT_DEBUG("Reply Record (first element) 0x%x", fins_in->ctrlFrame.replyRecord);
		PRINT_DEBUG("Sender Id %d", ff->ctrlFrame.senderID);
		PRINT_DEBUG("Serial number %d", ff->ctrlFrame.serial_num);
	}

}

/**@brief copies the contents of one fins frame into another
 * @param dst is the pointer to the fins frame being written to
 * @param src is the pointer to the source fins frame
 * */
void copy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src) {

	if (src->dataOrCtrl == DATA) {

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->dataFrame, &src->dataFrame, sizeof(src->dataFrame));

		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pdu = src->dataFrame.pdu;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->metaData = src->metaData;

	} else if (src->dataOrCtrl == CONTROL) {

		PRINT_DEBUG("control fins frame");

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->ctrlFrame, &src->ctrlFrame, sizeof(src->ctrlFrame));
		dst->ctrlFrame.opcode = src->ctrlFrame.opcode;
		dst->ctrlFrame.param_id = src->ctrlFrame.param_id;
		dst->ctrlFrame.data = src->ctrlFrame.data;
		//dst->ctrlFrame.replyRecord = (void *) src->ctrlFrame.data;
		dst->ctrlFrame.senderID = src->ctrlFrame.senderID;
		dst->ctrlFrame.serial_num = src->ctrlFrame.serial_num;
	}

}

struct finsFrame *cloneFinsFrame(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *params_clone = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params_clone);

	metadata *params = ff->metaData;
	if (params) {
		if (metadata_copy(params, params_clone) == META_FALSE) {
			PRINT_ERROR("todo error");
		}
	} else {
		PRINT_ERROR("todo error");
	}

	struct finsFrame *ff_clone = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff_clone->dataOrCtrl = ff->dataOrCtrl;
	ff_clone->destinationID.id = ff->destinationID.id;
	ff_clone->destinationID.next = ff->destinationID.next; //TODO this is a list copy all of them?
	ff_clone->metaData = params_clone;

	if (ff_clone->dataOrCtrl == CONTROL) {
		ff_clone->ctrlFrame.senderID = ff->ctrlFrame.senderID;
		ff_clone->ctrlFrame.serial_num = gen_control_serial_num(); //ff->ctrlFrame.serial_num; //TODO should this occur?
		ff_clone->ctrlFrame.opcode = ff->ctrlFrame.opcode;
		ff_clone->ctrlFrame.param_id = ff->ctrlFrame.param_id; //TODO error msg code

		ff_clone->ctrlFrame.data_len = ff->ctrlFrame.data_len; //Add in the header size for this, too
		if (ff_clone->ctrlFrame.data_len) {
			ff_clone->ctrlFrame.data = (uint8_t *) secure_malloc(ff_clone->ctrlFrame.data_len);
			memcpy(ff_clone->ctrlFrame.data, ff->ctrlFrame.data, ff_clone->ctrlFrame.data_len);
		} else {
			PRINT_DEBUG("here");
			ff_clone->ctrlFrame.data = NULL;
		}
		PRINT_DEBUG("Exited: orig: ff=%p, meta=%p, data=%p; clone: ff=%p, meta=%p, data=%p",
				ff, ff->metaData, ff->ctrlFrame.data, ff_clone, ff_clone->metaData, ff_clone->ctrlFrame.data);
	} else if (ff_clone->dataOrCtrl == DATA) {
		ff_clone->dataFrame.directionFlag = ff->dataFrame.directionFlag;

		ff_clone->dataFrame.pduLength = ff->dataFrame.pduLength; //Add in the header size for this, too
		if (ff_clone->dataFrame.pduLength) {
			ff_clone->dataFrame.pdu = (uint8_t *) secure_malloc(ff_clone->dataFrame.pduLength);
			memcpy(ff_clone->dataFrame.pdu, ff->dataFrame.pdu, ff_clone->dataFrame.pduLength);
		} else {
			PRINT_DEBUG("here");
			ff_clone->dataFrame.pdu = NULL;
		}
		PRINT_DEBUG("Exited: orig: ff=%p, meta=%p, pdu=%p; clone: ff=%p, meta=%p, pdu=%p",
				ff, ff->metaData, ff->dataFrame.pdu, ff_clone, ff_clone->metaData, ff_clone->dataFrame.pdu);
	} else {
		PRINT_ERROR("todo error");
	}

	return ff_clone;
}

int freeFinsFrame(struct finsFrame *ff) {
	if (ff == NULL) {
		return (0);
	}

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);
	if (ff->dataOrCtrl == CONTROL) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->ctrlFrame.data) {
			PRINT_DEBUG("Freeing data=%p", ff->ctrlFrame.data);
			free(ff->ctrlFrame.data);
		}
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->dataFrame.pdu) {
			PRINT_DEBUG("Freeing pdu=%p", ff->dataFrame.pdu);
			free(ff->dataFrame.pdu);
		}
	} else {
		//dataOrCtrl uninitialized
		PRINT_ERROR("todo error");
	}

	free(ff);
	return (1);
}

int serializeCtrlFrame(struct finsFrame * ff, unsigned char **buffer)
/* serializes a fins control frame for transmission to an external process
 * - pass it the frame (finsFrame) and it will fill in the pointer to the frame, uchar*
 * -- and return the length of the array (return int);
 * - this is used to send a control frame to an external app
 * - we can't send pointers outside of a process
 * - called by the sender
 */
{
	// MST: I think we only need to worry about a subset of these, mainly the read/read reply/set
	// types. For the others, why don't you serialize part of the info and send that or
	// just not do anything -- use your best judgement.
	// We probably won't know how all of the information is stored unless we go nuts
	// and start including a whole bunch of stuff -- this is where it would be great
	// to have objects that could serialize themselves. Oh well.

	//switch (finsFrame->opcode)
	// CTRL_READ_PARAM: ...
	// CTRL_READ_PARAM_REPLY: ...
	// CTRL_ALERT: ...
	// CTRL_ERROR: ...
	// CTRL_SET_PARAM:...
	// CTRL_EXEC: ...
	// CTRL_EXEC_REPLY: ...
	// default: ...

	//load buffer

	//	if(sizeof(buffer) < sizeof(itoa(ff->dataOrCtrl) + ff->destinationID.id + ff->ctrlFrame.name + itoa(ff->ctrlFrame.opcode) + itoa(ff->ctrlFrame.senderID) + itoa(ff->ctrlFrame.serial_num) + sizeof((char)ff->ctrlFrame.data)))

	PRINT_DEBUG("In serializeCtrlFrame!");

	//PRINT_DEBUG("temp_buffer: %ssize of temp_buffer: %d",temp_buffer,sizeof(temp_buffer));

	//initialize buffer

	int buf_size = /*strlen((char *) ff->ctrlFrame.data_old) + strlen((char *) ff->ctrlFrame.name) + */3 * sizeof(unsigned char) + 2 * sizeof(int)
			+ sizeof(unsigned short int) + sizeof(unsigned int);

	//PRINT_DEBUG("SIZE OF BUF_SIZE = %d", buf_size);

	*buffer = (unsigned char *) secure_malloc(buf_size);

	unsigned char * temporary = *buffer;

	//DATA OR CONTROL
	memcpy((unsigned char *) *buffer, &(ff->dataOrCtrl), sizeof(unsigned char));
	//PRINT_DEBUG("buffer1:%s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//DESTINATION ID
	memcpy((unsigned char *) *buffer, &(ff->destinationID.id), sizeof(unsigned char));
	//PRINT_DEBUG("buffer2:%s",*buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//send size of name first
	int temp = 0; //strlen((char *) ff->ctrlFrame.name);
	memcpy((unsigned char *) *buffer, &temp, sizeof(int));

	//increment pointer
	*buffer += sizeof(int);

	//NAME
	//strcat((unsigned char *)*buffer, ff->ctrlFrame.name);
	//memcpy((unsigned char *) *buffer, ff->ctrlFrame.name, temp);
	//PRINT_DEBUG("buffer3:%s", *buffer);

	//increment pointer
	*buffer += temp;

	//OPCODE
	//	strncat((unsigned char *)*buffer, (unsigned char *) (&(htonl(ff->ctrlFrame.opcode))), sizeof(int));
	memcpy((unsigned char *) *buffer, &(ff->ctrlFrame.opcode), sizeof(unsigned short int));
	//PRINT_DEBUG("buffer4 = %s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned short int);

	//SENDERID
	//strncat((unsigned char *)*buffer, &(ff->ctrlFrame.senderID),sizeof(unsigned char *));
	memcpy((unsigned char *) *buffer, &(ff->ctrlFrame.senderID), sizeof(unsigned char));
	//PRINT_DEBUG("buffer5:%s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//SERIALNUM
	memcpy((unsigned char *) *buffer, &(ff->ctrlFrame.serial_num), sizeof(unsigned int));
	//PRINT_DEBUG("buffer6: %s", *buffer);

	*buffer += sizeof(unsigned int);

	//fill in known/common parts
	switch (ff->ctrlFrame.opcode) {
	case CTRL_READ_PARAM:
		break;

	case CTRL_READ_PARAM_REPLY:
		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//send size of data first
		//temp = strlen((char *) (ff->ctrlFrame.data_old));
		//memcpy((unsigned char *) *buffer, &temp, sizeof(int));

		//increment buffer
		*buffer += sizeof(int);

		//send data itself
		//memcpy(*buffer, (char *) (ff->ctrlFrame.data_old), temp);
		//PRINT_DEBUG("CSP: buffer7 = %s, temp = %d, data = %s", *buffer,temp,((char *)(ff->ctrlFrame.data)));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;

	}

	//decrement pointer
	*buffer = temporary;
	PRINT_DEBUG("Final value of buffer:%s", *buffer);

	return strlen((char *) (*buffer));
}

struct finsFrame* unserializeCtrlFrame(unsigned char * buffer, int length)
/* does the opposite of serializeCtrlFrame; used to reconstruct a controlFrame
 * - pass it the byte array and the length and it will give you a pointer to the
 * -- struct.
 * - called by the receiver
 */
{
	/* again, we'll probably only have to deal with a subset of the types here.
	 * I'm OK with just doing what we know we'll pass back and forth and we
	 * can worry about the rest later. -- MST
	 */
	PRINT_DEBUG("In unserializeCtrlFrame!");

	struct finsFrame * ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	memset(ff, 0, sizeof(struct finsFrame));

	//	PRINT_DEBUG("The value of buffer = %s", buffer,length);

	//DATA OR CONTROL
	memcpy(&(ff->dataOrCtrl), (unsigned char *) buffer, sizeof(unsigned char));
	//PRINT_DEBUG("buffer1 = %s, dataOrCtrl = %d", buffer,ff->dataOrCtrl);
	buffer += sizeof(unsigned char);

	//DESTINATION ID
	memcpy(&(ff->destinationID), (unsigned char *) buffer, sizeof(unsigned char));
	//PRINT_DEBUG("buffer2 = %s, destination = %d", buffer,ff->destinationID.id);
	buffer += sizeof(unsigned char);

	//NAME
	//retrieve size of name first
	int temp = 0;
	memcpy(&temp, (unsigned char *) buffer, sizeof(int));
	buffer += sizeof(int);

	//PRINT_DEBUG("temp = %d", temp);

	//retrieve the name
	//ff->ctrlFrame.name = fins_malloc(temp);
	//memcpy(ff->ctrlFrame.name, (unsigned char *) buffer, temp);
	//PRINT_DEBUG("buffer3 = %s, name = %s", buffer,ff->ctrlFrame.name);
	buffer += temp;

	//OPCODE
	memcpy(&(ff->ctrlFrame.opcode), (unsigned char *) buffer, sizeof(unsigned short int));
	//PRINT_DEBUG("buffer4 = %s, opcode = %d", buffer,ff->ctrlFrame.opcode);
	buffer += sizeof(unsigned short int);

	//SENDERID
	memcpy(&(ff->ctrlFrame.senderID), (unsigned char *) buffer, sizeof(unsigned char));
	//PRINT_DEBUG("buffer5 = %s, senderID = %d", buffer,ff->ctrlFrame.senderID);
	buffer += sizeof(unsigned char);

	//SERIALNUM
	memcpy(&(ff->ctrlFrame.serial_num), (unsigned char *) buffer, sizeof(unsigned int));
	//PRINT_DEBUG("buffer6 = %s, serial_num = %d", buffer,ff->ctrlFrame.serial_num);
	buffer += sizeof(unsigned int);

	//DATA
	//fill in known/common parts
	switch (ff->ctrlFrame.opcode) {
	case CTRL_READ_PARAM:

		break;

	case CTRL_READ_PARAM_REPLY:

		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//retrieve size of data first
		temp = 0;
		memcpy(&temp, (unsigned char *) buffer, sizeof(int));

		//PRINT_DEBUG("CSP: buffer6.25 = %s", buffer);

		//increment buffer
		buffer += sizeof(int);
		//PRINT_DEBUG("CSP: buffer6.5 = %s", buffer);

		//retrieve data itself
		//ff->ctrlFrame.data_old = fins_malloc(temp);
		//memcpy((char *) (ff->ctrlFrame.data_old), buffer, temp);
		//PRINT_DEBUG("CSP: buffer7 = %s, temp = %d, data = %s", buffer, temp,(char *)(ff->ctrlFrame.data));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;
	}

	return ff;
}
