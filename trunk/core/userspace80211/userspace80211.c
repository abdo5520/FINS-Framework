#include "userspace80211.h"


#include <switch.h>
static struct fins_proto_module userspace80211_proto = { .module_id = USERSPACE80211_ID, .name = "userspace80211", .running_flag = 1, };

pthread_t stub80211_to_userspace80211_thread;
pthread_t switch_to_userspace80211_thread;

sem_t userspace80211_sockets_sem;
struct userspace80211_socket userspace80211_sockets[MAX_SOCKETS];

struct userspace80211_call userspace80211_calls[MAX_CALLS];
struct userspace80211_call_list *expired_call_list;

int userspace80211_thread_count;

uint8_t userspace80211_interrupt_flag;


int init_stub80211_nl(void) {
	int sockfd;
	int ret;

	sem_init(&nl_stub80211_sem, 0, 1);

	// Get a netlink socket descriptor
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_stub80211);
	if (sockfd == -1) {
		return -1;
	}

	// Populate local_stub80211_sockaddress
	memset(&local_stub80211_sockaddress, 0, sizeof(local_stub80211_sockaddress));
	local_stub80211_sockaddress.nl_family = AF_NETLINK;
	local_stub80211_sockaddress.nl_pad = 0;
	local_stub80211_sockaddress.nl_pid = getpid(); //pthread_self() << 16 | getpid(),	// use second option for multi-threaded process
	local_stub80211_sockaddress.nl_groups = 0; // unicast

	// Bind the local netlink socket
	ret = bind(sockfd, (struct sockaddr*) &local_stub80211_sockaddress, sizeof(local_stub80211_sockaddress));
	if (ret == -1) {
		return -1;
	}

	// Populate kernel_stub80211_sockaddress
	memset(&kernel_stub80211_sockaddress, 0, sizeof(kernel_stub80211_sockaddress));
	kernel_stub80211_sockaddress.nl_family = AF_NETLINK;
	kernel_stub80211_sockaddress.nl_pad = 0;
	kernel_stub80211_sockaddress.nl_pid = 0; // to kernel
	kernel_stub80211_sockaddress.nl_groups = 0; // unicast

	return sockfd;
}

/*
 * Sends len bytes from buf on the sockfd.  Returns 0 if successful.  Returns -1 if an error occurred, errno set appropriately.
 */
int send_stub80211(int sockfd, uint8_t *buf, size_t len, int flags) {
	PRINT_DEBUG("Entered: sockfd=%d, buf=%p, len=%d, flags=0x%x", sockfd, buf, len, flags);

	int ret; // Holds system call return values for error checking

	// Begin send message section
	// Build a message to send to the kernel
	int nlmsg_len = NLMSG_LENGTH(len);
	struct nlmsghdr *nlh = (struct nlmsghdr *) secure_malloc(nlmsg_len);
	memset(nlh, 0, nlmsg_len);

	nlh->nlmsg_len = nlmsg_len;
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0; // arbitrary value
	nlh->nlmsg_seq = 0; // sequence number
	nlh->nlmsg_pid = getpid(); // pthread_self() << 16 | getpid();	// use the second one for multiple threads
	nlh->nlmsg_flags = flags;

	// Insert payload (memcpy)
	memcpy(NLMSG_DATA(nlh), buf, len);

	// finish message packing
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &kernel_stub80211_sockaddress;
	msg.msg_namelen = sizeof(kernel_stub80211_sockaddress);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the message
	PRINT_DEBUG("Sending message to kernel");

	secure_sem_wait(&nl_stub80211_sem);
	ret = sendmsg(sockfd, &msg, 0);
	sem_post(&nl_stub80211_sem);

	free(nlh);

	if (ret == -1) {
		return -1;
	} else {
		return 0;
	}
}





int nack_send_stub80211(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret;

	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, nack=%d", call_id, call_index, call_type, msg, NACK);

	int buf_len = sizeof(struct nl_userspace80211_to_stub80211);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_userspace80211_to_stub80211 *hdr = (struct nl_userspace80211_to_stub80211 *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = NACK;
	hdr->msg = msg;

	ret = send_stub80211(nl_stub80211_sockfd, buf, buf_len, 0);
	free(buf);

	return ret == 1; //TODO change to ret_val ?
}

int ack_send_stub80211(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret;

	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, ack=%d", call_id, call_index, call_type, msg, ACK);

	int buf_len = sizeof(struct nl_userspace80211_to_stub80211);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_userspace80211_to_stub80211 *hdr = (struct nl_userspace80211_to_stub80211 *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = ACK;
	hdr->msg = msg;

	ret = send_stub80211(nl_stub80211_sockfd, buf, buf_len, 0);
	free(buf);

	return ret == 1; //TODO change to ret_val ?
}

int userspace80211_to_switch(struct finsFrame *ff) {
	return module_to_switch(&userspace80211_proto, ff);
}

int userspace80211_fcf_to_switch(uint8_t dest_id, metadata *params, uint32_t serial_num, uint16_t opcode, uint32_t param_id) {
	PRINT_DEBUG("Entered: module_id=%d, meta=%p, serial_num=%u, opcode=%u, param_id=%u", dest_id, params, serial_num, opcode, param_id);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = CONTROL;
	ff->destinationID.id = dest_id;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->ctrlFrame.senderID = USERSPACE80211_ID;
	ff->ctrlFrame.serial_num = serial_num;
	ff->ctrlFrame.opcode = opcode;
	ff->ctrlFrame.param_id = param_id;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("ff=%p, meta=%p", ff, params);
	if (userspace80211_to_switch(ff)) {
		return 1;
	} else {
		free(ff);
		return 0;
	}
}

int userspace80211_fdf_to_switch(uint8_t dest_id, uint8_t *data, uint32_t data_len, metadata *params) {
	PRINT_DEBUG("Entered: module_id=%u, data=%p, data_len=%u, meta=%p", dest_id, data, data_len, params);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = dest_id;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DIR_DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	PRINT_DEBUG("sending: ff=%p, meta=%p", ff, params);
	if (userspace80211_to_switch(ff)) {
		return 1;
	} else {
		PRINT_ERROR("freeing: ff=%p", ff);
		free(ff);
		return 0;
	}
}

int userspace80211_setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int userspace80211_setBlocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0; //TODO verify is right?
	return ioctl(fd, FIOBIO, &flags);
#endif
}


void userspace80211_out_ff(struct nl_stub80211_to_userspace80211 *hdr, uint8_t *msg_pt, int msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);

	//############################### Debug
#ifdef DEBUG
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	if (0) {
		print_hex(msg_len, msg_pt);
	}
#endif
	//###############################

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR("call_index out of range: call_index=%d", hdr->call_index);
		return;
	}

	switch (hdr->call_type) {

	default:
		PRINT_ERROR("Dropping, received unknown call_type=%d", hdr->call_type);
		break;
	}
}

void test_func_userspace80211(struct nl_stub80211_to_userspace80211 *hdr, uint8_t *msg_pt, int msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d, call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);

	//############################### Debug
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	print_hex(msg_len, msg_pt);
	//###############################

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR("call_index out of range: call_index=%d", hdr->call_index);
		return;
	}

	int events;
	uint8_t *pt = msg_pt;

	events = *(int *) pt;
	pt += sizeof(int);

	if (events) {

	}

	if (pt - msg_pt != msg_len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - msg_pt, msg_len);
		//nack_send_stub80211(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}
}

void *stub80211_to_userspace80211(void *local) {
	PRINT_IMPORTANT("Entered");

	int ret;

	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	int nfds = 1;
	struct pollfd fds[nfds];
	fds[0].fd = nl_stub80211_sockfd;
	//fds[0].events = POLLIN | POLLERR; //| POLLPRI;
	fds[0].events = POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND; //| POLLERR;
	//fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	PRINT_DEBUG("fd: sock=%d, events=%x", nl_stub80211_sockfd, fds[0].events);
	int time = 1000;

	uint8_t *recv_buf;
	recv_buf = (uint8_t *) secure_malloc(RECV_BUFFER_SIZE + 16); //16 = NLMSGHDR size

	struct sockaddr sockaddr_sender; // Needed for recvfrom
	socklen_t sockaddr_senderlen = sizeof(sockaddr_sender); // Needed for recvfrom
	memset(&sockaddr_sender, 0, sockaddr_senderlen);

	struct nlmsghdr *nlh;
	void *nl_buf; // Pointer to your actual data payload
	struct nl_stub80211_to_userspace80211_hdr *msg_hdr;
	int nl_len; //, part_len; // Size of your actual data payload
	uint8_t *part_pt;

	uint8_t *msg_buf = NULL;
	int msg_len = -1;
	uint8_t *msg_pt = NULL;

	struct nl_stub80211_to_userspace80211 *hdr;
	int okFlag, doneFlag = 0;
	//int test_msg_len;

	//int pos;

	PRINT_DEBUG("Waiting for message from kernel");

	int counter = 0;
	while (userspace80211_proto.running_flag) {
		++counter;
		PRINT_DEBUG("NL counter = %d", counter);

		//TODO find alternative? convert to event driven
		if (0) { //works but over taxes the nl socket, causing sendmsg to take 10+ ms.
			userspace80211_setNonblocking(nl_stub80211_sockfd);
			do {
				ret = recvfrom(nl_stub80211_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
			} while (userspace80211_proto.running_flag && ret <= 0);

			if (!userspace80211_proto.running_flag) {
				break;
			}

			if (ret == -1) {
				perror("recvfrom() caused an error");
				exit(-1);
			}

			userspace80211_setBlocking(nl_stub80211_sockfd);
		}
		if (0) { //works but blocks, so can't shutdown properly, have to double ^C or kill
			ret = recvfrom(nl_stub80211_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);

			if (!userspace80211_proto.running_flag) {
				break;
			}

			if (ret == -1) {
				perror("recvfrom() caused an error");
				exit(-1);
			}
		}
		if (1) { //works, appears to be minor overhead, select/poll have fd cap if increase num of nl sockets
			do {
				ret = poll(fds, nfds, time);
			} while (userspace80211_proto.running_flag && ret <= 0);

			if (!userspace80211_proto.running_flag) {
				break;
			}

			if (fds[0].revents & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
				ret = recvfrom(nl_stub80211_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
			} else {
				PRINT_ERROR("nl poll error");
				perror("nl poll");
				break;
			}
		}

		//PRINT_DEBUG("%d", sockaddr_sender);

		nlh = (struct nlmsghdr *) recv_buf;

		if ((okFlag = NLMSG_OK(nlh, ret))) {
			switch (nlh->nlmsg_type) {
			case NLMSG_NOOP:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP");
				break;
			case NLMSG_ERROR:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_ERROR");
				okFlag = 0;
				break;
			case NLMSG_OVERRUN:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_OVERRUN");
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE");
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default");
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len=%d", nl_len);
				if (nl_len < sizeof(struct nl_stub80211_to_userspace80211_hdr)) {
					PRINT_ERROR("todo error");
				}

				msg_hdr = (struct nl_stub80211_to_userspace80211_hdr *) nl_buf;
				//part_pt = nl_buf;
				//test_msg_len = *(int *) part_pt;
				//part_pt += sizeof(int);

				//PRINT_DEBUG("test_msg_len=%d, msg_len=%d", test_msg_len, msg_len);

				if (msg_len == -1) {
					msg_len = msg_hdr->msg_len;
				} else if (msg_len != msg_hdr->msg_len) {
					okFlag = 0;
					PRINT_ERROR("diff lengs: msg_len=%d, msg_hdr->msg_len=%d", msg_len, msg_hdr->msg_len);
					//could just malloc msg_buff again
					break;//might comment out or make so start new
				}

				//part_len = *(int *) part_pt;
				//part_pt += sizeof(int);
				if (msg_hdr->part_len > RECV_BUFFER_SIZE) {
					PRINT_ERROR("part len too big: part_len=%d, RECV_BUFFER_SIZE=%d", msg_hdr->part_len, RECV_BUFFER_SIZE);
				}

				//PRINT_DEBUG("part_len=%d", part_len);

				//pos = *(int *) part_pt;
				//part_pt += sizeof(int);
				if (msg_hdr->pos > msg_len || msg_hdr->pos != msg_pt - msg_buf) {
					if (msg_hdr->pos > msg_len) {
						PRINT_ERROR("pos > msg_len");
					} else {
						PRINT_ERROR("pos != msg_pt - msg_buf");
					}
				}

				//PRINT_DEBUG("pos=%d", pos);

				PRINT_DEBUG("msg_len=%d, part_len=%d, pos=%d, seq=%d", msg_len, msg_hdr->part_len, msg_hdr->pos, nlh->nlmsg_seq);

				if (nlh->nlmsg_seq == 0) {
					if (msg_buf != NULL) {
						PRINT_ERROR("error: msg_buf != NULL at new sequence, freeing");
						free(msg_buf);
					}
					msg_buf = (uint8_t *) secure_malloc(msg_len);
					msg_pt = msg_buf;
				}

				if (msg_pt != NULL) {
					part_pt = nl_buf + sizeof(struct nl_stub80211_to_userspace80211_hdr);
					msg_pt = msg_buf + msg_hdr->pos; //atm redundant, is for if out of sync msgs
					memcpy(msg_pt, part_pt, msg_hdr->part_len);
					msg_pt += msg_hdr->part_len;
				} else {
					PRINT_ERROR("error: msg_pt is NULL");
				}

				if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
					//doneFlag = 1; //not multi-part msg //removed multi
				}
				break;
			}
		}

		if (okFlag != 1) {
			doneFlag = 0;
			PRINT_ERROR("okFlag != 1");
			//send kernel a resend request
			//with pos of part being passed can store msg_buf, then recopy new part when received
		}

		if (doneFlag) {
			if (msg_len < sizeof(struct nl_stub80211_to_userspace80211)) {
				//TODOD error
				PRINT_ERROR("todo error");
			}

			hdr = (struct nl_stub80211_to_userspace80211 *) msg_buf;
			msg_pt = msg_buf + sizeof(struct nl_stub80211_to_userspace80211);
			msg_len -= sizeof(struct nl_stub80211_to_userspace80211);

			userspace80211_out_ff(hdr, msg_pt, msg_len);

			free(msg_buf);
			doneFlag = 0;
			msg_buf = NULL;
			msg_pt = NULL;
			msg_len = -1;
		}
	}

	PRINT_IMPORTANT("Total NL msgs: counter=%d", counter);

	free(recv_buf);
	close(nl_stub80211_sockfd);

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
}

void *switch_to_userspace80211(void *local) {
	PRINT_IMPORTANT("Entered");

	while (userspace80211_proto.running_flag) {
		userspace80211_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
}

void userspace80211_handle_to(struct userspace80211_call *call) { //TODO finish transitioning to this TO system
	PRINT_DEBUG("Entered: call=%p, call_index=%d", call, call->call_index);

	//TO for call
	//split call by call_type/sock_type, poll_timeout_tcp

	switch (call->call_type) {

	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call->call_type);
		//exit(1);
		break;
	}
}

void userspace80211_interrupt(void) {
	PRINT_DEBUG("Entered");

	int i = 0;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&userspace80211_sockets_sem);

	for (i = 0; i < MAX_CALLS; i++) {
		if (userspace80211_calls[i].sock_id != -1 && userspace80211_calls[i].to_flag) {
			userspace80211_calls[i].to_flag = 0;

			userspace80211_handle_to(&userspace80211_calls[i]);
		}
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&userspace80211_sockets_sem);
}

void userspace80211_get_ff(void) {
	struct finsFrame *ff;

	do {
		secure_sem_wait(userspace80211_proto.event_sem);
		secure_sem_wait(userspace80211_proto.input_sem);
		ff = read_queue(userspace80211_proto.input_queue);
		sem_post(userspace80211_proto.input_sem);
	} while (userspace80211_proto.running_flag && ff == NULL && !userspace80211_interrupt_flag); //TODO change logic here, combine with switch_to_userspace80211?

	if (!userspace80211_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == CONTROL) {
			userspace80211_fcf(ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				userspace80211_in_fdf(ff);
				PRINT_DEBUG("");
			} else { //directionFlag==DIR_DOWN
				PRINT_ERROR("todo error");
				//drop
			}
		} else {
			PRINT_ERROR("todo error");
		}
	} else if (userspace80211_interrupt_flag) {
		userspace80211_interrupt_flag = 0;

		userspace80211_interrupt();
	} else {
		PRINT_ERROR("todo error");
	}
}

void userspace80211_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		userspace80211_read_param_reply(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		userspace80211_set_param_reply(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		userspace80211_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		userspace80211_exec_reply(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		userspace80211_error(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void userspace80211_read_param_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for stub80211 pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&userspace80211_sockets_sem);

	int call_index = 0;
	uint32_t call_id = userspace80211_calls[call_index].call_id;
	uint32_t call_type = userspace80211_calls[call_index].call_type;

	uint64_t sock_id = userspace80211_calls[call_index].sock_id;
	int sock_index = userspace80211_calls[call_index].sock_index;

	uint32_t data = userspace80211_calls[call_index].data;



	if (userspace80211_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&userspace80211_sockets_sem);

		nack_send_stub80211(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&userspace80211_sockets_sem);

	switch (call_type) {
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call_type);
		//exit(1);
		break;
	}
}

void userspace80211_exec_reply_new(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//metadata *params = ff->metaData;
	switch (ff->ctrlFrame.param_id) {

	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void userspace80211_set_param_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for stub80211 pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&userspace80211_sockets_sem);
	int call_index = 0;
	if (call_index == -1) {
		PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&userspace80211_sockets_sem);

		freeFinsFrame(ff);
		return;
	}

	uint32_t call_id = userspace80211_calls[call_index].call_id;
	uint32_t call_type = userspace80211_calls[call_index].call_type;

	uint64_t sock_id = userspace80211_calls[call_index].sock_id;
	int sock_index = userspace80211_calls[call_index].sock_index;

	uint32_t data = userspace80211_calls[call_index].data;




	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&userspace80211_sockets_sem);

	switch (call_type) {

	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call_type);
		//exit(1);
		break;
	}
}

void userspace80211_exec(struct finsFrame *ff) {
	uint32_t protocol;
	uint32_t ret_msg;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *params = ff->metaData;
	switch (ff->ctrlFrame.param_id) {

		switch (protocol) {
		case IPPROTO_ICMP:
			//userspace80211_icmp_in_error(ff, src_ip, dst_ip);
			PRINT_ERROR("todo");
			break;
		case IPPROTO_TCP:
			//userspace80211_tcp_in_poll(ff, ret_msg);
			break;
		case IPPROTO_UDP:
			//userspace80211_udp_in_error(ff, src_ip, dst_ip);
			PRINT_ERROR("todo");
			break;
		default:
			//PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
			//freeFinsFrame(ff);
			break;
		}
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?

		ff->destinationID.id = ff->ctrlFrame.senderID;

		ff->ctrlFrame.senderID = USERSPACE80211_ID;
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		ff->ctrlFrame.ret_val = 0;

		userspace80211_to_switch(ff);
		break;
	}
}

void userspace80211_exec_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for stub80211 pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&userspace80211_sockets_sem);
	struct userspace80211_call *call = call_list_find_serial_num(expired_call_list, ff->ctrlFrame.serial_num);
	int call_index =0;
	if (call) {
		call_list_remove(expired_call_list, call);

		if (userspace80211_sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
			PRINT_ERROR("Exited, socket closed: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&userspace80211_sockets_sem);

			freeFinsFrame(ff);
			return;
		}
		//TODO something?
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&userspace80211_sockets_sem);

		switch (call->call_type) {
		default:
			PRINT_ERROR("Not supported dropping: call_type=%d", call->call_type);
			//exit(1);
			break;
		}
	} else {
		if (call_index == -1) {
			PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&userspace80211_sockets_sem);

			freeFinsFrame(ff);
			return;
		} else {
			uint32_t call_id = userspace80211_calls[call_index].call_id;

			int call_pid = userspace80211_calls[call_index].call_pid;
			uint32_t call_type = userspace80211_calls[call_index].call_type;

			uint64_t sock_id = userspace80211_calls[call_index].sock_id;
			int sock_index = userspace80211_calls[call_index].sock_index;

			uint32_t flags = userspace80211_calls[call_index].flags;
			uint32_t data = userspace80211_calls[call_index].data;

			uint64_t sock_id_new = userspace80211_calls[call_index].sock_id_new;
			int sock_index_new = userspace80211_calls[call_index].sock_index_new;


			if (userspace80211_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
				PRINT_ERROR("Exited, socket closed: ff=%p", ff);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&userspace80211_sockets_sem);

				nack_send_stub80211(call_id, call_index, call_type, 1);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&userspace80211_sockets_sem);

			switch (call_type) {
			default:
				PRINT_ERROR("Not supported dropping: call_type=%d", call_type);
				//exit(1);
				break;
			}
		}
	}
}

void userspace80211_error(struct finsFrame *ff) { //TODO expand for different error types, atm only for TTL expired/dest unreach
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	uint32_t protocol;
	uint32_t src_ip;
	uint32_t dst_ip;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_protocol", &protocol);
	secure_metadata_readFromElement(params, "send_src_ip", &src_ip);
	secure_metadata_readFromElement(params, "send_dst_ip", &dst_ip);

	//ff->ctrlFrame.data_len = sent->data_len;
	//ff->ctrlFrame.data = sent->data;

	switch (protocol) {

	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
		freeFinsFrame(ff);
		break;
	}
}

void userspace80211_in_fdf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, len=%d", ff, ff->metaData, ff->dataFrame.pduLength);

	uint32_t protocol = 0;
	uint32_t dst_ip = 0;
	uint32_t src_ip = 0;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "recv_protocol", &protocol);
	secure_metadata_readFromElement(params, "recv_src_ip", &src_ip);
	secure_metadata_readFromElement(params, "recv_dst_ip", &dst_ip);

	//##############################################
#ifdef DEBUG
	struct in_addr *temp = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
	if (src_ip) {
		temp->s_addr = htonl(src_ip);
	} else {
		temp->s_addr = 0;
	}
	struct in_addr *temp2 = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
	if (dst_ip) {
		temp2->s_addr = htonl(dst_ip);
	} else {
		temp2->s_addr = 0;
	}
	PRINT_DEBUG("ff=%p, prot=%u", ff, protocol);
	PRINT_DEBUG("src=%s (%u)", inet_ntoa(*temp), src_ip);
	PRINT_DEBUG("dst=%s (%u)", inet_ntoa(*temp2), dst_ip);

	free(temp);
	free(temp2);

	char *buf = (char *) secure_malloc(ff->dataFrame.pduLength + 1);
	memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	buf[ff->dataFrame.pduLength] = '\0';
	PRINT_DEBUG("pdulen=%u, pdu='%s'", ff->dataFrame.pduLength, buf);
	free(buf);
#endif
	//##############################################

	switch (protocol) {
	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
		freeFinsFrame(ff);
		break;
	}
}

void userspace80211_dummy(void) {

}

void userspace80211_init(void) {
	PRINT_IMPORTANT("Entered");
	userspace80211_proto.running_flag = 1;

	module_create_ops(&userspace80211_proto);
	module_register(&userspace80211_proto);

	//init_userspace80211Sockets();
	userspace80211_thread_count = 0;

	int i;
	sem_init(&userspace80211_sockets_sem, 0, 1);
	for (i = 0; i < MAX_SOCKETS; i++) {
		userspace80211_sockets[i].sock_id = -1;
		userspace80211_sockets[i].state = SS_FREE;
	}

	for (i = 0; i < MAX_CALLS; i++) {
		userspace80211_calls[i].call_id = -1;

		userspace80211_calls[i].to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
		userspace80211_calls[i].to_data->handler = intsem_to_handler;
		userspace80211_calls[i].to_data->flag = &userspace80211_calls[i].to_flag;
		userspace80211_calls[i].to_data->interrupt = &userspace80211_interrupt_flag;
		userspace80211_calls[i].to_data->sem = userspace80211_proto.event_sem;
		timer_create_to((struct to_timer_data *) userspace80211_calls[i].to_data);
	}

	expired_call_list = call_list_create(MAX_CALLS);

	//init the netlink socket connection to userspace80211
	nl_stub80211_sockfd = init_stub80211_nl();
	if (nl_stub80211_sockfd == -1) {
		perror("init_stub80211_nl() caused an error");
		exit(-1);
	}

	//prime the kernel to establish userspace80211's PID
	int userspace80211code = userspace80211_start_call;
	int ret;
	ret = send_stub80211(nl_stub80211_sockfd, (uint8_t *) &userspace80211code, sizeof(int), 0);
	if (ret != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_IMPORTANT("Connected to stub80211 at fd=%d", nl_stub80211_sockfd);
}

void userspace80211_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_IMPORTANT("Entered");

	secure_pthread_create(&stub80211_to_userspace80211_thread, fins_pthread_attr, stub80211_to_userspace80211, fins_pthread_attr);
	secure_pthread_create(&switch_to_userspace80211_thread, fins_pthread_attr, switch_to_userspace80211, fins_pthread_attr);
}

void userspace80211_shutdown(void) {
	PRINT_IMPORTANT("Entered");
	userspace80211_proto.running_flag = 0;
	sem_post(userspace80211_proto.event_sem);

	//prime the kernel to establish userspace80211's PID
	int userspace80211code = userspace80211_stop_call;
	int ret = send_stub80211(nl_stub80211_sockfd, (uint8_t *) &userspace80211code, sizeof(int), 0);
	if (ret) {
		PRINT_DEBUG("send_stub80211 failure");
		//perror("sendfins() caused an error");
	}
	PRINT_IMPORTANT("Disconnecting to stub80211 at fd=%d", nl_stub80211_sockfd);

	PRINT_IMPORTANT("Joining switch_to_userspace80211_thread");
	pthread_join(switch_to_userspace80211_thread, NULL);
	PRINT_IMPORTANT("Joining stub80211_to_userspace80211_thread");
	pthread_join(stub80211_to_userspace80211_thread, NULL); //TODO change thread so can be stopped, atm is blocking
}

void userspace80211_release(void) {
	PRINT_IMPORTANT("Entered");

	//unregister
	module_unregister(userspace80211_proto.module_id);

	//TODO free all module related mem




	sem_destroy(&nl_stub80211_sem);
	sem_destroy(&userspace80211_sockets_sem);

	module_destroy_ops(&userspace80211_proto);
}



/**

int main()
{



//init the netlink socket connection to stub80211
	nl_stub80211_sockfd = init_stub80211_nl();
	if (nl_stub80211_sockfd == -1) {
		perror("init_stub80211_nl() caused an error");
		exit(-1);
	}
	PRINT_IMPORTANT("user Side Printing started ");
	//prime the kernel to establish stub80211's PID
	int stub80211code = stub80211_start_call;
	int ret;
	ret = send_stub80211(nl_stub80211_sockfd, (uint8_t *) &stub80211code, sizeof(int), 0);
	if (ret != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_IMPORTANT("Connected to stub80211 at fd=%d", nl_stub80211_sockfd);

	int i;
	for ( i=0; i <= 1000; i++)
	{
	sleep (1);
	
	ret = send_stub80211(nl_stub80211_sockfd, (uint8_t *) &i, sizeof(int), 0);
		
	PRINT_IMPORTANT("counter i =  %d", i);

	}




}
*/


