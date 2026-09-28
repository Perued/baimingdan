// baimingdan.x
// 完整独立版本 - 不依赖 JDEnvAudit.x 里的任何辅助函数，自己带一套最简日志

#import <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <substrate.h>

#pragma mark - 自带的最简日志函数（不依赖外部任何东西）

static void BMDLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void BMDLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[baimingdan] %@ %@", [df stringFromDate:[NSDate date]], body];

    NSLog(@"%@", line);

    // 顺手写到沙盒文件里，方便事后拉日志（路径跟JDEnvAudit那份保持一致风格）
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [doc stringByAppendingPathComponent:@"baimingdan.log"];
    NSString *row = [line stringByAppendingString:@"\n"];
    NSData *data = [row dataUsingEncoding:NSUTF8StringEncoding];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [data writeToFile:path atomically:YES];
    } else {
        @try {
            [fh seekToEndOfFile];
            [fh writeData:data];
        } @finally {
            [fh closeFile];
        }
    }
}

// 安全打印一个指针"如果它碰巧是个OC对象"——带@try保护，
// 但注意：@try只能挡住OC/Foundation层面的异常，挡不住指针本身不合法导致的底层崩溃
static NSString *BMDSafeDesc(id obj) {
    if (!obj) return @"(nil)";
    @try {
        return [obj description] ?: @"(null desc)";
    } @catch (__unused NSException *e) {
        return @"(description threw)";
    }
}

#pragma mark - 遗漏补充6: 直接对i_userId_config处理函数按地址下钩子(非ObjC方法,原始地址hook)

// 静态链接时算出来的偏移量(相对__TEXT段基址)，来自对DadaStaff二进制的反汇编分析：
// 0x1f4560 = 那段处理"i_userId_config"等一批配置名的Swift函数入口
#define TARGET_FUNC_OFFSET 0x1f4560

// 原函数指针，%orig的手动版本
static void (*orig_userIdConfigFunc)(void *x0, void *x1, void *x2, void *x3);

// 替换后的函数：先把参数打出来，再原样传给真正的函数继续执行
static void hooked_userIdConfigFunc(void *x0, void *x1, void *x2, void *x3) {
    BMDLog(@"==== [疑似] i_userId_config 处理函数被调用 ====");
    BMDLog(@"  x0(可能是self/上下文) = %p", x0);
    BMDLog(@"  x1(可能是参数1)       = %p", x1);
    BMDLog(@"  x2(可能是参数2)       = %p", x2);
    BMDLog(@"  x3(可能是参数3)       = %p", x3);

    BMDLog(@"  x0 尝试当作OC对象打印: %@", BMDSafeDesc((__bridge id)x0));
    BMDLog(@"  x1 尝试当作OC对象打印: %@", BMDSafeDesc((__bridge id)x1));
    BMDLog(@"  x2 尝试当作OC对象打印: %@", BMDSafeDesc((__bridge id)x2));
    BMDLog(@"  x3 尝试当作OC对象打印: %@", BMDSafeDesc((__bridge id)x3));

    orig_userIdConfigFunc(x0, x1, x2, x3);
}

%ctor {
    BMDLog(@"===== baimingdan tweak ctor 启动 =====");

    const struct mach_header *header = _dyld_get_image_header(0);
    uintptr_t base = (uintptr_t)header;

    void *targetAddr = (void *)(base + TARGET_FUNC_OFFSET);
    BMDLog(@"准备hook i_userId_config处理函数, 运行时地址 = %p (基址=%p + 偏移0x%lx)",
           targetAddr, (void *)base, (unsigned long)TARGET_FUNC_OFFSET);

    MSHookFunction(targetAddr, (void *)hooked_userIdConfigFunc, (void **)&orig_userIdConfigFunc);
}
