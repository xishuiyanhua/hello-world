/*
 * =====================================================================================
 *
 *       Filename:  alarm.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2010骞?6鏈?8鏃?14鏃?4鍒?5绉?CST
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  xzhang (xzhang), zxy_9090@163.com
 *        Company:  HongDian
 *
 * =====================================================================================
 */

#include "alarm.h"
#include "alarm_config.h"
#include "ahead.h"
#include "productdef.h"
#include "command.h"
#include "hp_misc.h"

#define ALARM_COMMAND_ID				0401
#define SET_ALARM_CONFIG_COMMAND_ID		0402
#define GET_ALARM_CONFIG_COMMAND_ID		0403

int reset = 0;
int reread = 0;
int io_in_raw_status = 0;//bit=0表示有报警发生
int vl_raw_status = 0;
int md_raw_status = 0;
int speed_raw_status = 0;
int g_alarm_led_duration = 0;
int g_vi_fd;
int g_ds_fd;
int g_io_fd;
trigger_t *g_p_trigger = NULL;


/*---------------------------------------------------------------------------
 * function name : reset_handler
 *   description : 重启进程
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
void reset_handler(int signo)
{
    reset = 1;
    return;
}



/*---------------------------------------------------------------------------
 * function name : reset_handler
 *   description : 重读配置
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
void reread_handler(int signo)
{
    reread = 1;
    return;
}



/*---------------------------------------------------------------------------
 * function name : handle_signal
 *   description : 信号处理函数
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int handle_signal(void)
{
    sigset_t newmask, oldmask, zeromask;

    sigemptyset(&newmask);
    sigemptyset(&zeromask);
    sigaddset(&newmask, SIGINT);
    sigaddset(&newmask, SIGTERM);
    sigaddset(&newmask, SIGQUIT);
    sigaddset(&newmask, SIGHUP); 
 
    if (0 > sigprocmask(SIG_BLOCK, &newmask, &oldmask))
    {
        msg(M_ERROR, "sigpromask error! %s, %d", __FILE__, __LINE__);
        return -1;
    }

    while ((0 == reread) && (0 == reset))
    {
        if (-1 != sigsuspend(&zeromask))
        {
            return -1;
        }
    }

    msg(M_DEBU, "signal is %d", reset);

    if (0 > sigprocmask(SIG_SETMASK, &oldmask, NULL))
    {
        msg(M_ERROR, "sigpromask error! %s, %d", __FILE__, __LINE__);
        return -1;
    }

    if (1 == reread)
    {
        msg(M_DEBU, "alarm process reread the config file");
        reread =0;
        return 0;
    }
    else if(1 == reset)
    {
        msg(M_DEBU, "alarm process has been reset");
        return 1;
    }

    return 0;
}



/*---------------------------------------------------------------------------
 * function name : recv_alarm_msg
 *   description : 接收UNIX域通信
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int recv_alarm_msg(int alarm_fd, xml_object **alarm_root)
{
    struct sockaddr_storage cli_addr;
    socklen_t addrlen = sizeof(cli_addr);
    char rcvbuf[ALARM_RECEIVE_BUF_LEN] = {0};
    int rcvlen = 0;
    int fd = alarm_fd;
	
    if ((0 > alarm_fd) || (NULL == alarm_root))
    {
		msg(M_ERROR, "recv alarm msg parameters is NULL! %s, %d", __FILE__, __LINE__);
		return G3_ERROR_ARGS;
    }

	memset(rcvbuf, 0, ALARM_RECEIVE_BUF_LEN);
    rcvlen = recvfrom(fd, rcvbuf, ALARM_RECEIVE_BUF_LEN, 0, (struct sockaddr*)&cli_addr, &addrlen);
    if (0 > rcvlen)
    {
        if (EWOULDBLOCK != errno)
        {
            msg(M_ERROR, "system error! %s, %d", __FILE__, __LINE__);
            return G3_ERROR;
        }
    }

	//printf("recv alarm msg is :%s\n", ircvbuf);
    msg(M_DEBU, "recv alarm msg is :%s", rcvbuf);    

    *alarm_root = xml_str_to_onetree(rcvbuf, &rcvlen);
    return G3_SUCCEED;
}


/***********************************************************************
*
*	概述：		解析报警命令
*	输入参数：	root	报警命令树
*	输出参数：	无
*	返回值：	NULL 解析失败
*				解析成功则返回报警类型
*	功能：		解析报警树，返回报警类型
*
***********************************************************************/
static char *parse_alarm_message(xml_object *root)
{
	char *content = NULL;
	int command_id = 0;

	command_id = parse_command_head(root);
	if(command_id != ALARM_COMMAND_ID)
	{
		msg(M_ERRO, "parse command head error!");
		return NULL;
	}

	content = xml_find_child_node_content(root, "type");
	if (content == NULL)
	{
		msg(M_ERRO, "cannot find node <type>");
		return NULL;
	}

	return content;
}


/*---------------------------------------------------------------------------
 * function name : parse_alarm_msg
 *   description : 解析报警信息
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
char *parse_alarm_msg(xml_object *alarm_root)
{
    if (NULL == alarm_root)
    {
        msg(M_ERROR, "parse alarm msg parameters is NULL! %s, %d", __FILE__, __LINE__);
        return NULL;
    }

    char *name = parse_alarm_message(alarm_root);
    if (NULL == name)
    {
        msg(M_ERROR, "get msg name is NULL! %s, %d", __FILE__, __LINE__);
    }

    msg(M_DEBU, "alarm event name = %s! %s, %d", name,  __FILE__, __LINE__);
 
    return name;
}




/*---------------------------------------------------------------------------
 * function name : parse_alarm_speed
 *   description : 解析报警速度
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
char *parse_alarm_speed(xml_object *alarm_root)
{
    if (NULL == alarm_root)
    {
        msg(M_ERROR, "parse alarm speed parameters is NULL! %s, %d", __FILE__, __LINE__);
        return NULL;
    }

    char *content = xml_get_childcontent(alarm_root, "speed");
    if (NULL == content)
    {
        msg(M_INFO, "alarm speed is NULL!");
    }

    msg(M_INFO, "alarm speed is %s!", content);

    return content;     
}


/*---------------------------------------------------------------------------
 * function name : alarm_io_in_req
 *   description : IO-IN请求
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
xml_object *alarm_io_in_req(alarm_io_t *iin)
{
	if (iin == NULL)
	{
		return NULL;
	}

	int i;
	xml_object *tmp = NULL;
	xml_object *msg = xml_create_node("message", NULL);
	xml_object *body = xml_create_node("body", NULL);
	xml_object *head = create_command_head(0x03);
	xml_append_child(msg, head);
	xml_append_child(msg, body);

    for (i = 0; i < iin->num; i++)
	{
		char cont[8] = {0};
		snprintf(cont, sizeof(cont), "%d", iin->io[i].chn);
		tmp = xml_create_node("io_in", NULL);
		xml_append_child(tmp, xml_create_node("chn", cont));
		xml_append_child(body, tmp);
	}

	return msg;
}



/*---------------------------------------------------------------------------
 * function name : alarm_io_in_req
 *   description : IO-IN应答
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int alarm_io_in_ack(xml_object *ack)
{
	int status = 0;
	char *content = NULL;
	xml_object *tmp = NULL;
	xml_object *msg = NULL;
	xml_object *body = NULL;
	msg = ack;

	content = xml_find_child_node_content(msg, "id");
	if (NULL != content)
	{
	
	   	if ((0x03 | 0x80) != atoi(content))
	   	{
	        msg(M_INFO, "ack cmd id(0x%x) err", atoi(content));
	        return G3_ERROR;
	   	}
   	}
   	else
   	{
        return G3_ERROR;
   	}	

	body = xml_find_child(msg, "body");

	tmp = NULL;
	while(NULL != (tmp = xml_find_nextchild(body, tmp)))
	{
		int chn, value;
		char *content = NULL;

		content = xml_get_childcontent(tmp, "chn");
		if (NULL != content)
		{
			chn = atoi(content);
		}
		content = xml_get_childcontent(tmp, "value");
		if (NULL != content)
		{
			value = atoi(content);
		}
		
		status = (status | (value << chn));
	}
	status = 0xff & (~status);

	msg(M_INFO, "status = 0x%x", status);
	return status;
}



 

/*---------------------------------------------------------------------------
 * function name : send_io_in_req
 *   description : IO-IN状态请求
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int send_io_in_req(int fd)
{
	int i;
	int ret;
	alarm_io_t alarm_io;
	xml_object *req = NULL;
	
	if (fd < 0)
	{
		return G3_ERROR;
	}

	alarm_io.num = 8;
	for (i = 0; i < alarm_io.num; i++)
	{
		alarm_io.io[i].chn = i;
	}

	req = alarm_io_in_req(&alarm_io);

	ret = xml_treetofd_udp(req, fd, 0);
	if (G3_SUCCEED != ret)
	{
		xml_del_tree(req);
		return G3_ERROR;
	}

	xml_del_tree(req);
	return G3_SUCCEED;
}



/*---------------------------------------------------------------------------
 * function name : get_ms_raw_status
 *   description : 获取MD/SPEED信息
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int get_ms_raw_status(int fd)
{
    xml_object *alarm_root = NULL;
    char *name = NULL;  
    //int ret;	
	 
    if (fd < 0)
    {
		return G3_ERROR;
    }
	
    if (recv_alarm_msg(fd, &alarm_root) < 0)
    {
		return G3_ERROR;
    }
    
    name = parse_alarm_message(alarm_root);
    if (NULL != name)
    {
		if (0 == strncmp(name, "md", 2))
		{
			char content[4] = {0};
			strncpy(content, &name[2], 1);
			md_raw_status = 0x01 << (atoi(content) - 1);
			//printf("%s:%d: md_raw_status:0x%08X, get md alarm:%s\n", __FILE__, __LINE__, md_raw_status, name);
		}
		else if (0 == strncmp(name, "speed", 5))
		{
			char content[8] = {0};
			strcpy(content, &name[5]);
			speed_raw_status = atoi(content);	        
		}
    }

    xml_del_tree(alarm_root);       

    return G3_SUCCEED;
}



/*---------------------------------------------------------------------------
 * function name : get_ms_raw_status
 *   description : 获取MD/SPEED信息
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int get_io_in_raw_status(int fd)
{
	xml_object *alarm_ack = NULL;
	
	if (fd < 0)
	{
		msg(M_INFO, "get_io_in_raw_status paras invalid");
		return G3_ERROR;
	}

	recv_alarm_msg(fd, &alarm_ack);
	io_in_raw_status = alarm_io_in_ack(alarm_ack);
	//msg(M_INFO, "io_in_raw_status = %d", io_in_raw_status);
	xml_del_tree(alarm_ack);
	return G3_SUCCEED;
}



/*---------------------------------------------------------------------------
 * function name : get_vl_raw_status
 *   description : 获取视频丢失信息
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int get_vl_raw_status(int fd)
{
	unsigned long status = 0;

	if (fd < 0)
	{
		msg(M_INFO, "get_vl_raw_status paras invalid");
		return G3_ERROR;
	}
	/*mod by xzhang 20121128 begin*/
//#ifdef TW2868
if(AD_TW2868 == g_AdType_app)
{
	if (0 != ioctl(fd, TW2868CMD_GET_VL, &status))
	{
		msg(M_ERRNO, "read i2c reg error");
		return G3_ERROR;
	}
	vl_raw_status = (0xff & status);
}
//#else
else if(AD_TW2865 == g_AdType_app)
{	
	if (0 != ioctl(fd, TW2865CMD_GET_VL, &status))
	{
		msg(M_ERROR, "read i2c reg error");
		return G3_ERROR;
	}
	vl_raw_status = (0xf & status);
}
//#endif
	/*mod by xzhang 20121128 end*/
	msg(M_INFO, "video lost status=%x", vl_raw_status);

	return G3_SUCCEED;
}

/*---------------------------------------------------------------------------
 * function name : get_ms_raw_status
 *   description : 获取MD/SPEED信息
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int alarm_config_init(void)
{
//    int ret1;
//    int ret2;
    int ret;
    
    g_p_trigger = NULL;   
   
    while ((G3_ERROR == get_alarm_trigger(HD_ALARM_MAIN_FILE, &g_p_trigger)) && (NULL == g_p_trigger))     
    {
        ret = handle_signal();

        if (1 == ret || -1 == ret)
        {
            return G3_ERROR;
        }
        else if (0 == ret)
        {
            continue;
        }
    }

    msg(M_INFO,"trigger:%s\n", g_p_trigger->name);
    return G3_SUCCEED;
}



/*---------------------------------------------------------------------------
 * function name : alarm_communication_init
 *   description : 建立UNIX域通信服务器、客户端、视频输入
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int alarm_communication_init(void)
{
	g_ds_fd = alarm_domainserver_fd(ALARM_UNIX_FILE);
	if (g_ds_fd < 0)
	{
		msg(M_INFO, "create alarm domain server fd failed");
		return G3_ERROR; 
	}
	
	g_vi_fd = alarm_videoin_fd(VIDEO_DEVICE);
	if (g_vi_fd < 0)
	{
		msg(M_INFO, "open alarm video in fd failed");
		return G3_ERROR;
	}

	g_io_fd = alarm_domainclient_fd(MCU_PATH);
	if (g_io_fd < 0)
	{
		msg(M_INFO, "create alarm domain server fd failed");
		return G3_ERROR;
	}

	return G3_SUCCEED;
}



/*---------------------------------------------------------------------------
 * function name : alarm_communication_init
 *   description : 释放UNIX域通信服务器、客户端、视频输入所占用的资源
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
void alarm_communication_exit(void)
{
	char buf[16] = {0};
	
	close(g_ds_fd);
	close(g_vi_fd);
	close(g_io_fd);

	snprintf(buf, sizeof(buf), "%s%d", IIN_PATH, getpid());
	msg(M_INFO, "unlink(%s)", buf);
	unlink(ALARM_UNIX_FILE);
	unlink(buf);
	return;
}

#define ALARM_KEEPALIVE_INVAL 30
int alarm_keepalive(void)
{
	static long last_time = 0;
	long cur_time = 0;

	cur_time = get_run_time();
	if (cur_time > last_time + ALARM_KEEPALIVE_INVAL)
	{
		last_time = cur_time;
		change_mp_status1("alarm", "report");
	}

	return 0;
}


/*---------------------------------------------------------------------------
 * function name : handle_event
 *   description : 处理报警事件和触发报警动作
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int handle_event(trigger_t *p_trigger)
{
	int fd;
	int ret = 0;
//	long last_time;
//	long now_time;
	fd_set rfds;
	struct timeval t;
	t.tv_sec = 0;
	t.tv_usec = 0;
	int vl_raw_status_old = 0;
        
    if (NULL == p_trigger) 	
	{
		msg(M_DEBU, "handle_alarm paras invalid");
		return G3_ERROR;
	}

	alarm_communication_init();
	fd = (g_ds_fd > g_io_fd) ? (g_ds_fd + 1) : (g_io_fd + 1); 
	
	while ((0 == reset) && (0 == reread))
	{
	    FD_ZERO(&rfds);
	    FD_SET(g_ds_fd, &rfds);
	    FD_SET(g_io_fd, &rfds);
	    usleep(1000000);

		msg(M_INFO,"IO request!\n");
		if(0 > (ret = send_io_in_req(g_io_fd) ))
		{
			printf("IO request failed!\n");
			msg(M_INFO,"IO request failed\n");
		}

		ret = select(fd, &rfds, NULL, NULL, &t);
		if (ret < 0)
		{
		    if (EINTR == errno)
			{
				continue;
			}
			return G3_ERROR;
		}
		else if(ret == 0)
		{
			msg(M_INFO, "time out");		
			continue;
		}
		
	    if (FD_ISSET(g_ds_fd, &rfds) > 0)
	    {
			get_ms_raw_status(g_ds_fd);
	     }

	    if (FD_ISSET(g_io_fd, &rfds) > 0)
	    {
	    	msg(M_DEBU, "FD_ISSET g_io_fd");
	    	get_io_in_raw_status(g_io_fd);
	    }

	 	get_vl_raw_status(g_vi_fd);    

		//添加视频丢失日志，added by yuxiaozhu 2013.10.15
		if (0 != vl_raw_status && vl_raw_status != vl_raw_status_old)
		{
			local_log_save(2, "************************视频丢失************************");
		}
		vl_raw_status_old = vl_raw_status;

		handle_alarm(p_trigger);
		alarm_keepalive();
	}

    if ((1 == reset) || (1 == reread))
    { 
		release_alarm(p_trigger);
		del_alarm_trigger(p_trigger);
		p_trigger = NULL;
		g_p_trigger = NULL;        
		LEDCtrl(LED_ID_ALARM,  LED_OP_OFF);
		alarm_communication_exit();
		sleep(1);
    }
    msg(M_INFO, "EXIT.......");
    return G3_SUCCEED;	
}


/*---------------------------------------------------------------------------
 * function name : main
 *   description : 报警模块入口
 *         input : 输入参数
 *        notice : 
 *
 *        author : xzhang
 *       history : new
 *-------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    int ret = 0;   
 
    hp_signal(SIGINT, reset_handler);
    hp_signal(SIGTERM, reset_handler);
    hp_signal(SIGQUIT, reset_handler);
    hp_signal(SIGHUP, reread_handler);

    openmsg(MSG_EASY, "/var/log/alarm.log", "alarm", 90628);
	//openmsg( MSG_SYSLOG, NULL, "alarm", 0 );
    msg(M_DEBU, "enter the main ---------- ALARM");
		
	ret = alarm_config_init();
	if (ret < 0)
	{
		msg(M_ERROR, "config init error!");
		return G3_ERROR;
	}

    ret = handle_event(g_p_trigger);
    if (0 > ret)
    {
        msg(M_ERROR, "handle event error!");
        return G3_ERROR;
    }

    return G3_SUCCEED;
}

