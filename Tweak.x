// JDEnvAudit.x
// Theos: 加入 Tweak 的 FILES，并链接 -framework Foundation -framework UIKit
#import <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#define HOOK_PREFIX @"[JDEnvAudit]"
#define kDumpMaxDepth 5
#define kDumpMaxCollection 64

#pragma mark - File logger (sandbox)

static NSString *JDLogFilePath(void) {
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (doc.length == 0) {
            doc = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:doc withIntermediateDirectories:YES attributes:nil error:nil];
        path = [doc stringByAppendingPathComponent:@"JDEnvAudit.log"];
    });
    return path;
}

static dispatch_queue_t JDLogQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("jd.env.audit.log", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

static void JDFileAppend(NSString *line) {
    if (!line.length) return;
    dispatch_async(JDLogQueue(), ^{
        NSString *path = JDLogFilePath();
        NSString *row = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
        NSData *data = [row dataUsingEncoding:NSUTF8StringEncoding];
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            [@"===== JDEnvAudit log start =====\n" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [data writeToFile:path atomically:YES];
            return;
        }
        @try {
            [fh seekToEndOfFile];
            [fh writeData:data];
            [fh synchronizeFile];
        } @finally {
            [fh closeFile];
        }
    });
}

static void JDLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void JDLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *body = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"%@ %@ %@", HOOK_PREFIX, [df stringFromDate:[NSDate date]], body];
    NSLog(@"%@", line);
    JDFileAppend(line);
}

#pragma mark - Dump helpers & Utility

static NSString *JDDumpDescribe(id obj, NSInteger depth, NSMutableSet *seen);

static NSString *JDSafeDesc(id obj) {
    if (!obj) return @"(nil)";
    @try { return [obj description] ?: @"(null desc)"; }
    @catch (__unused NSException *e) { return @"(description threw)"; }
}

static NSString *JDYN(BOOL v) {
    return v ? @"YES" : @"NO";
}

static NSString *JDIndent(NSInteger depth) {
    if (depth <= 0) return @"";
    return [@"" stringByPaddingToLength:(NSUInteger)depth * 2 withString:@" " startingAtIndex:0];
}

#pragma mark - Dump helpers (Safe filtered)

static BOOL JDSkipWalk(id obj) {
    if (!obj) {
        return YES;
    }
    Class cls = object_getClass(obj);
    if (!cls || class_isMetaClass(cls)) {
        return YES;
    }
    NSString *name = NSStringFromClass(cls);
    if (name.length == 0) {
        return YES;
    }
    if ([name hasPrefix:@"WK"] || [name hasPrefix:@"_WK"] ||
        [name hasPrefix:@"UI"] || [name hasPrefix:@"NS"] ||
        [name hasPrefix:@"CA"] || [name hasPrefix:@"AV"] ||
        [name hasPrefix:@"CF"] || [name hasPrefix:@"JS"] ||
        [name hasPrefix:@"Web"] || [name hasPrefix:@"_UI"] ||
        [name hasPrefix:@"OS_"] || [name hasPrefix:@"__NS"] ||
        [name hasPrefix:@"_NS"]) {
        return YES;
    }
    if ([obj isKindOfClass:[UIResponder class]]) {
        return YES;
    }
    if ([obj isKindOfClass:[NSURLSession class]] ||
        [obj isKindOfClass:[NSURLSessionTask class]] ||
        [obj isKindOfClass:[NSOperationQueue class]] ||
        [obj isKindOfClass:[NSThread class]]) {
        return YES;
    }
    return NO;
}

static BOOL JDSkipProp(NSString *key, const char *attrs) {
    if ([key localizedCaseInsensitiveContainsString:@"delegate"]) {
        return YES;
    }
    if ([key localizedCaseInsensitiveContainsString:@"weak"]) {
        return YES;
    }
    if (!attrs) {
        return NO;
    }
    NSString *a = @(attrs);
    if ([a containsString:@",W"] || [a hasPrefix:@"W"] || [a containsString:@"W,"]) {
        return YES;
    }
    return NO;
}

static NSString *JDDumpDescribe(id obj, NSInteger depth, NSMutableSet *seen);

static NSString *JDDumpIvarsAndProps(id obj, NSInteger depth, NSMutableSet *seen) {
    if (JDSkipWalk(obj)) {
        return @"";
    }
    NSMutableString *out = [NSMutableString string];
    Class cls = object_getClass(obj);
    NSString *pad = JDIndent(depth);

    while (cls && cls != [NSObject class]) {
        NSString *clsName = NSStringFromClass(cls);
        if ([clsName hasPrefix:@"NS"] || [clsName hasPrefix:@"UI"] ||
            [clsName hasPrefix:@"WK"] || [clsName hasPrefix:@"_WK"]) {
            break;
        }
        [out appendFormat:@"\n%@-- class %@ --", pad, clsName];

        unsigned int pCount = 0;
        objc_property_t *props = class_copyPropertyList(cls, &pCount);
        for (unsigned int i = 0; i < pCount; i++) {
            const char *name = property_getName(props[i]);
            const char *attrs = property_getAttributes(props[i]);
            NSString *key = name ? @(name) : @"(anon)";
            if (JDSkipProp(key, attrs)) {
                [out appendFormat:@"\n%@  prop %@ SKIP", pad, key];
                continue;
            }
            id val = nil;
            @try {
                val = [obj valueForKey:key];
            } @catch (__unused NSException *e) {
                val = @"<KVC failed>";
            }
            NSString *attrStr = attrs ? @(attrs) : @"";
            [out appendFormat:@"\n%@  prop %@ [%@] = %@", pad, key, attrStr, JDDumpDescribe(val, depth + 1, seen)];
        }
        if (props) {
            free(props);
        }

        unsigned int iCount = 0;
        Ivar *ivars = class_copyIvarList(cls, &iCount);
        for (unsigned int i = 0; i < iCount; i++) {
            const char *iname = ivar_getName(ivars[i]);
            const char *itype = ivar_getTypeEncoding(ivars[i]);
            NSString *key = iname ? @(iname) : @"(anon-ivar)";
            const char *enc = itype ? itype : "";
            if ([key localizedCaseInsensitiveContainsString:@"delegate"]) {
                [out appendFormat:@"\n%@  ivar %@ SKIP", pad, key];
                continue;
            }
            id val = nil;
            @try {
                if (enc[0] == '@' || enc[0] == '#') {
                    val = object_getIvar(obj, ivars[i]);
                } else {
                    val = [NSString stringWithFormat:@"<non-object type %s>", enc];
                }
            } @catch (__unused NSException *e) {
                val = @"<ivar read failed>";
            }
            [out appendFormat:@"\n%@  ivar %@ [%s] = %@", pad, key, enc, JDDumpDescribe(val, depth + 1, seen)];
        }
        if (ivars) {
            free(ivars);
        }
        cls = class_getSuperclass(cls);
    }
    return out;
}

static NSString *JDDumpDescribe(id obj, NSInteger depth, NSMutableSet *seen) {
    if (!obj || obj == (id)kCFNull || [obj isKindOfClass:[NSNull class]]) {
        return @"(nil)";
    }
    if (depth > kDumpMaxDepth) {
        return [NSString stringWithFormat:@"<%@ %p depth-limit>",
                NSStringFromClass(object_getClass(obj)), obj];
    }
    NSValue *box = [NSValue valueWithNonretainedObject:obj];
    if ([seen containsObject:box]) {
        return [NSString stringWithFormat:@"<%@ %p CYCLIC>", NSStringFromClass(object_getClass(obj)), obj];
    }
    [seen addObject:box];

    NSString *clsName = NSStringFromClass(object_getClass(obj));
    NSString *pad = JDIndent(depth);

    if ([obj isKindOfClass:[NSString class]] ||
        [obj isKindOfClass:[NSNumber class]] ||
        [obj isKindOfClass:[NSValue class]] ||
        [obj isKindOfClass:[NSDate class]] ||
        [obj isKindOfClass:[NSURL class]]) {
        return [NSString stringWithFormat:@"(%@) %@", clsName, JDSafeDesc(obj)];
    }
    if ([obj isKindOfClass:[NSData class]]) {
        NSData *data = (NSData *)obj;
        NSUInteger n = MIN(data.length, (NSUInteger)64);
        const unsigned char *b = (const unsigned char *)data.bytes;
        NSMutableString *hex = [NSMutableString string];
        for (NSUInteger i = 0; i < n; i++) {
            [hex appendFormat:@"%02x", b[i]];
        }
        if (data.length > n) {
            [hex appendString:@"..."];
        }
        return [NSString stringWithFormat:@"(NSData len=%lu hex=%@)", (unsigned long)data.length, hex];
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)obj;
        NSMutableString *s = [NSMutableString stringWithFormat:@"(NSArray count=%lu)", (unsigned long)arr.count];
        NSUInteger n = MIN(arr.count, (NSUInteger)kDumpMaxCollection);
        for (NSUInteger i = 0; i < n; i++) {
            [s appendFormat:@"\n%@[%lu] %@", pad, (unsigned long)i, JDDumpDescribe(arr[i], depth + 1, seen)];
        }
        if (arr.count > n) {
            [s appendFormat:@"\n%@... truncated", pad];
        }
        return s;
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dic = (NSDictionary *)obj;
        NSMutableString *s = [NSMutableString stringWithFormat:@"(NSDictionary count=%lu)", (unsigned long)dic.count];
        NSUInteger i = 0;
        for (id k in dic) {
            if (i >= kDumpMaxCollection) {
                [s appendFormat:@"\n%@... truncated", pad];
                break;
            }
            i++;
            [s appendFormat:@"\n%@%@ = %@", pad, JDSafeDesc(k), JDDumpDescribe(dic[k], depth + 1, seen)];
        }
        return s;
    }
    if ([obj isKindOfClass:[NSSet class]]) {
        NSSet *set = (NSSet *)obj;
        NSMutableString *s = [NSMutableString stringWithFormat:@"(NSSet count=%lu)", (unsigned long)set.count];
        NSUInteger i = 0;
        for (id e in set) {
            if (i >= kDumpMaxCollection) {
                break;
            }
            i++;
            [s appendFormat:@"\n%@- %@", pad, JDDumpDescribe(e, depth + 1, seen)];
        }
        return s;
    }

    if (JDSkipWalk(obj)) {
        return [NSString stringWithFormat:@"<%@ %p> desc=%@", clsName, obj, JDSafeDesc(obj)];
    }

    NSMutableString *s = [NSMutableString stringWithFormat:@"<%@ %p> desc=%@", clsName, obj, JDSafeDesc(obj)];
    [s appendString:JDDumpIvarsAndProps(obj, depth, seen)];
    return s;
}


static void JDDumpRet(NSString *where, id ret) {
    NSMutableSet *seen = [NSMutableSet set];
    Class cls = ret ? object_getClass(ret) : Nil;
    JDLog(@"%@ retClass=%@ isa=%@ ptr=%p desc=%@",
          where,
          ret ? NSStringFromClass([ret class]) : @"(nil)",
          cls ? NSStringFromClass(cls) : @"(nil)",
          ret, JDSafeDesc(ret));
    JDLog(@"%@ DUMP:\n%@", where, JDDumpDescribe(ret, 0, seen));
}

static void JDDumpPrim(NSString *where, NSString *val) {
    JDLog(@"%@ PRIM %@", where, val);
}
// ▼▼▼▼▼ 新增的上传抓取辅助函数放在这里 ▼▼▼▼▼
#pragma mark - Upload dump helper

static void JDDumpUpload(NSString *tag, id payload) {
    JDLog(@"==== UPLOAD %@ ====", tag);
    if ([payload isKindOfClass:[NSData class]]) {
        NSData *data = (NSData *)payload;
        NSString *asStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (asStr.length > 0) {
            JDLog(@"==== UPLOAD %@ UTF8:\n%@", tag, asStr);
            id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json) {
                JDDumpRet([tag stringByAppendingString:@" JSON"], json);
                return;
            }
        }
    }
    JDDumpRet(tag, payload);
}
// ▲▲▲▲▲ 新增结束 ▲▲▲▲▲
#pragma mark - 1. DDJailBrokenMonter

%hook DDJailBrokenMonter

+ (id)defaultManger {
    id r = %orig();
    JDDumpRet(@"+[DDJailBrokenMonter defaultManger]", r);
    return r;
}

+ (BOOL)DDIsJailbreak {
    BOOL r = %orig();
    JDDumpPrim(@"+[DDJailBrokenMonter DDIsJailbreak]", JDYN(r));
    return r;
}

+ (id)DDisInjectDylibName {
    id r = %orig();
    JDDumpRet(@"+[DDJailBrokenMonter DDisInjectDylibName]", r);
    return r;
}

- (id)ddHasDylibNameList {
    id r = %orig();
    JDDumpRet(@"-[DDJailBrokenMonter ddHasDylibNameList]", r);
    return r;
}

%end

#pragma mark - 2. UIDevice (Expand)

%hook UIDevice

- (BOOL)ndd_isJailbroken {
    BOOL r = %orig();
    JDDumpPrim(@"-[UIDevice ndd_isJailbroken]", JDYN(r));
    return r;
}

- (BOOL)ndd_isSimulator {
    BOOL r = %orig();
    JDDumpPrim(@"-[UIDevice ndd_isSimulator]", JDYN(r));
    return r;
}

- (id)ndd_phoneNetInfo {
    id r = %orig();
    JDDumpRet(@"-[UIDevice ndd_phoneNetInfo]", r);
    return r;
}

- (id)ndd_phoneNetType {
    id r = %orig();
    JDDumpRet(@"-[UIDevice ndd_phoneNetType]", r);
    return r;
}

- (id)ndd_IMSI {
    id r = %orig();
    JDDumpRet(@"-[UIDevice ndd_IMSI]", r);
    return r;
}

- (id)JRRisk_getGatewayIPAddress {
    id r = %orig();
    JDDumpRet(@"-[UIDevice JRRisk_getGatewayIPAddress]", r);
    return r;
}

- (id)JRRisk_getNetmask {
    id r = %orig();
    JDDumpRet(@"-[UIDevice JRRisk_getNetmask]", r);
    return r;
}

- (id)JRRisk_getMacAddress {
    id r = %orig();
    JDDumpRet(@"-[UIDevice JRRisk_getMacAddress]", r);
    return r;
}

- (id)JRRisk_localIP {
    id r = %orig();
    JDDumpRet(@"-[UIDevice JRRisk_localIP]", r);
    return r;
}

- (id)jdjr_getGatewayIPAddress {
    id r = %orig();
    JDDumpRet(@"-[UIDevice jdjr_getGatewayIPAddress]", r);
    return r;
}

- (id)jdjr_getNetmask {
    id r = %orig();
    JDDumpRet(@"-[UIDevice jdjr_getNetmask]", r);
    return r;
}

- (id)jdjr_getMacAddress {
    id r = %orig();
    JDDumpRet(@"-[UIDevice jdjr_getMacAddress]", r);
    return r;
}

- (id)jdjr_localIP {
    id r = %orig();
    JDDumpRet(@"-[UIDevice jdjr_localIP]", r);
    return r;
}

%end

#pragma mark - 3. SystemInfo

%hook SystemInfo

+ (BOOL)isJailBroken {
    BOOL r = %orig();
    JDDumpPrim(@"+[SystemInfo isJailBroken]", JDYN(r));
    return r;
}

+ (id)jailBreaker {
    id r = %orig();
    JDDumpRet(@"+[SystemInfo jailBreaker]", r);
    return r;
}

%end

#pragma mark - 4. JDJR_HackersInfo (all methods from header)

%hook JDJR_HackersInfo

+ (id)dylibs {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo dylibs]", r);
    return r;
}
+ (BOOL)isFil {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isFil]", JDYN(r));
    return r;
}
+ (BOOL)isEmb {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isEmb]", JDYN(r));
    return r;
}
+ (BOOL)isAppstoreChannel {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isAppstoreChannel]", JDYN(r));
    return r;
}
+ (BOOL)isCall {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isCall]", JDYN(r));
    return r;
}
+ (long long)ret {
    long long r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo ret]", @(r).stringValue);
    return r;
}
+ (id)reDtt {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo reDtt]", r);
    return r;
}
+ (BOOL)is64Bit {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo is64Bit]", JDYN(r));
    return r;
}
+ (BOOL)mshk {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo mshk]", JDYN(r));
    return r;
}
+ (long long)hk {
    long long r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo hk]", @(r).stringValue);
    return r;
}
+ (id)hkDtt {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo hkDtt]", r);
    return r;
}
+ (BOOL)checkByInaccessibleFiles {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByInaccessibleFiles]", JDYN(r));
    return r;
}
+ (BOOL)checkByFstab {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByFstab]", JDYN(r));
    return r;
}
+ (BOOL)checkBySymbolicLink {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkBySymbolicLink]", JDYN(r));
    return r;
}
+ (BOOL)checkByEnv {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByEnv]", JDYN(r));
    return r;
}
+ (BOOL)checkByDylibs {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByDylibs]", JDYN(r));
    return r;
}
+ (BOOL)checkBySys {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkBySys]", JDYN(r));
    return r;
}
+ (BOOL)checkByApplications {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByApplications]", JDYN(r));
    return r;
}
+ (BOOL)checkByCydia {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByCydia]", JDYN(r));
    return r;
}
+ (BOOL)checkByBinPath {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByBinPath]", JDYN(r));
    return r;
}
+ (BOOL)checkByPath {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkByPath]", JDYN(r));
    return r;
}
+ (BOOL)checkJailBreak {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo checkJailBreak]", JDYN(r));
    return r;
}
+ (BOOL)judgementFrida5 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementFrida5]", JDYN(r));
    return r;
}
+ (BOOL)judgementFrida4 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementFrida4]", JDYN(r));
    return r;
}
+ (BOOL)judgementFrida3 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementFrida3]", JDYN(r));
    return r;
}
+ (BOOL)judgementFrida2 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementFrida2]", JDYN(r));
    return r;
}
+ (BOOL)judgementFrida1 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementFrida1]", JDYN(r));
    return r;
}
+ (long long)frida {
    long long r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo frida]", @(r).stringValue);
    return r;
}
+ (id)fridaDetect {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo fridaDetect]", r);
    return r;
}
+ (BOOL)judgementJailbreak6 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak6]", JDYN(r));
    return r;
}
+ (BOOL)judgementJailbreak5 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak5]", JDYN(r));
    return r;
}
+ (BOOL)judgementJailbreak4 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak4]", JDYN(r));
    return r;
}
+ (BOOL)judgementJailbreak3 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak3]", JDYN(r));
    return r;
}
+ (BOOL)judgementJailbreak2 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak2]", JDYN(r));
    return r;
}
+ (BOOL)judgementJailbreak1 {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo judgementJailbreak1]", JDYN(r));
    return r;
}
+ (long long)jail {
    long long r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo jail]", @(r).stringValue);
    return r;
}
+ (BOOL)isVPNOn {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isVPNOn]", JDYN(r));
    return r;
}
+ (BOOL)isProxyOpened {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isProxyOpened]", JDYN(r));
    return r;
}
+ (id)isHeadSetPlugging {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo isHeadSetPlugging]", r);
    return r;
}
+ (BOOL)isSimulator {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_HackersInfo isSimulator]", JDYN(r));
    return r;
}
+ (id)judgementJailbreak {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo judgementJailbreak]", r);
    return r;
}
+ (id)jailbrokenDevice {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo jailbrokenDevice]", r);
    return r;
}
+ (id)isDebug {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo isDebug]", r);
    return r;
}
+ (id)getBuildversion {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo getBuildversion]", r);
    return r;
}
+ (id)getBuildRelease {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo getBuildRelease]", r);
    return r;
}
+ (id)getHardware {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HackersInfo getHardware]", r);
    return r;
}

%end

#pragma mark - 5. JDJRFridaCheck

%hook JDJRFridaCheck

+ (id)getAllProcesses {
    id r = %orig();
    JDDumpRet(@"+[JDJRFridaCheck getAllProcesses]", r);
    return r;
}
+ (BOOL)checkSuspiciousProcess {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkSuspiciousProcess]", JDYN(r));
    return r;
}
+ (BOOL)checkSuspiciousFridaProcess {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkSuspiciousFridaProcess]", JDYN(r));
    return r;
}
+ (BOOL)checkPselectFlag {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkPselectFlag]", JDYN(r));
    return r;
}
+ (BOOL)canOpenLocalConnection:(int)arg1 {
    BOOL r = %orig(arg1);
    JDDumpPrim(@"+[JDJRFridaCheck canOpenLocalConnection:]", [NSString stringWithFormat:@"port=%d ret=%@", arg1, JDYN(r)]);
    return r;
}
+ (BOOL)checkAllPorts {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkAllPorts]", JDYN(r));
    return r;
}
+ (BOOL)checkOpenedPorts {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkOpenedPorts]", JDYN(r));
    return r;
}
+ (BOOL)checkExistenceOfSuspiciousFiles {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkExistenceOfSuspiciousFiles]", JDYN(r));
    return r;
}
+ (BOOL)checkExistenceOfSuspiciousFilesWithFrida {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkExistenceOfSuspiciousFilesWithFrida]", JDYN(r));
    return r;
}
+ (BOOL)checkExistenceOfSuspiciousFilesWithHook {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkExistenceOfSuspiciousFilesWithHook]", JDYN(r));
    return r;
}
+ (BOOL)checkDyld:(id)arg1 {
    BOOL r = %orig(arg1);
    JDLog(@"+[JDJRFridaCheck checkDyld:] arg=%@ ret=%@", JDSafeDesc(arg1), JDYN(r));
    return r;
}
+ (BOOL)checkSSLDyld:(id)arg1 {
    BOOL r = %orig(arg1);
    JDLog(@"+[JDJRFridaCheck checkSSLDyld:] arg=%@ ret=%@", JDSafeDesc(arg1), JDYN(r));
    return r;
}
+ (BOOL)checkHookDyld:(id)arg1 {
    BOOL r = %orig(arg1);
    JDLog(@"+[JDJRFridaCheck checkHookDyld:] arg=%@ ret=%@", JDSafeDesc(arg1), JDYN(r));
    return r;
}
+ (BOOL)checkFridaDyld {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkFridaDyld]", JDYN(r));
    return r;
}
+ (BOOL)checkFridaDyld:(id)arg1 {
    BOOL r = %orig(arg1);
    JDLog(@"+[JDJRFridaCheck checkFridaDyld:] arg=%@ ret=%@", JDSafeDesc(arg1), JDYN(r));
    return r;
}
+ (void)setCheckDetail:(id)arg1 type:(unsigned long long)arg2 {
    JDLog(@"+[JDJRFridaCheck setCheckDetail:type:] type=%llu", arg2);
    JDDumpRet(@"+[JDJRFridaCheck setCheckDetail:] ARG", arg1);
    %orig(arg1, arg2);
}
+ (id)getCheckDetail {
    id r = %orig();
    JDDumpRet(@"+[JDJRFridaCheck getCheckDetail]", r);
    return r;
}
+ (int)checkReverseTool {
    int r = %orig();
    JDDumpPrim(@"+[JDJRFridaCheck checkReverseTool]", @(r).stringValue);
    return r;
}

%end

#pragma mark - 6. EnvDetection / Manager / Hacker / Sam Env

%hook JDJREnvDetection
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDJREnvDetection sharedInstance]", r);
    return r;
}
- (int)detectSimulator {
    int r = %orig();
    JDDumpPrim(@"-[JDJREnvDetection detectSimulator]", @(r).stringValue);
    return r;
}
- (int)detectJiabroken {
    int r = %orig();
    JDDumpPrim(@"-[JDJREnvDetection detectJiabroken]", @(r).stringValue);
    return r;
}
%end

%hook JDJREnvDetectManager
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDJREnvDetectManager sharedInstance]", r);
    return r;
}
- (void)monitorRecordVideo {
    JDLog(@"-[JDJREnvDetectManager monitorRecordVideo]");
    %orig();
}
- (id)getEnvMsg:(id)arg1 deviceId:(id)arg2 {
    JDLog(@"-[JDJREnvDetectManager getEnvMsg:deviceId:] deviceId=%@", JDSafeDesc(arg2));
    JDDumpRet(@"getEnvMsg ARG1", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"-[JDJREnvDetectManager getEnvMsg:deviceId:]", r);
    return r;
}
- (void)getEnvHacker {
    JDLog(@"-[JDJREnvDetectManager getEnvHacker]");
    %orig();
}
- (void)postEnvData:(id)arg1 {
    JDDumpRet(@"-[JDJREnvDetectManager postEnvData:] ARG", arg1);
    %orig(arg1);
}
- (id)encryptEnvDetectData:(id)arg1 deviceId:(id)arg2 {
    JDDumpRet(@"encryptEnvDetectData INPUT", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"encryptEnvDetectData RET", r);
    return r;
}
%end

%hook JDJRHacker
+ (void)SET_HT_FLAG_iOS:(unsigned long long)arg1 {
    JDDumpPrim(@"+[JDJRHacker SET_HT_FLAG_iOS:]", @(arg1).stringValue);
    %orig(arg1);
}
+ (unsigned long long)get_ht_flag {
    unsigned long long r = %orig();
    JDDumpPrim(@"+[JDJRHacker get_ht_flag]", @(r).stringValue);
    return r;
}
%end

%hook JDJR_Sam_EnvDetect
+ (id)encryptEnvDetectData:(id)arg1 deviceId:(id)arg2 {
    JDDumpRet(@"+[JDJR_Sam_EnvDetect encryptEnvDetectData:] INPUT", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JDJR_Sam_EnvDetect encryptEnvDetectData:] RET", r);
    return r;
}
%end

%hook JDJR_Sam_RiskDetect
+ (id)getScreenDetect {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Sam_RiskDetect getScreenDetect]", r);
    return r;
}
%end

#pragma mark - 7. Hardware / Device / CPU / Battery / Net

%hook JDJR_HardwareInfo
+ (id)shareInstance {
    id r = %orig();
    JDDumpRet(@"+[JDJR_HardwareInfo shareInstance]", r);
    return r;
}
- (id)getAllDeviceInfo {
    id r = %orig();
    JDDumpRet(@"-[JDJR_HardwareInfo getAllDeviceInfo]", r);
    return r;
}
- (id)getDeviceInfoWithCollectionArray:(id)arg1 {
    JDDumpRet(@"getDeviceInfoWithCollectionArray ARG", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"getDeviceInfoWithCollectionArray RET", r);
    return r;
}
- (id)getAllProperties {
    id r = %orig();
    JDDumpRet(@"-[JDJR_HardwareInfo getAllProperties]", r);
    return r;
}
%end

%hook JDJR_DeviceInfo
+ (id)getANumList {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo getANumList]", r);
    return r;
}
+ (BOOL)isCpScreen {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_DeviceInfo isCpScreen]", JDYN(r));
    return r;
}
+ (BOOL)isMacApp {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_DeviceInfo isMacApp]", JDYN(r));
    return r;
}
+ (id)permissionForIDFA {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo permissionForIDFA]", r);
    return r;
}
+ (id)bsCheck {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo bsCheck]", r);
    return r;
}
%end

%hook JDJR_CPUInfo
+ (id)cpuAbi {
    id r = %orig();
    JDDumpRet(@"+[JDJR_CPUInfo cpuAbi]", r);
    return r;
}
+ (float)get_cpu_usage {
    float r = %orig();
    JDDumpPrim(@"+[JDJR_CPUInfo get_cpu_usage]", @(r).stringValue);
    return r;
}
+ (id)get_cpu_num {
    id r = %orig();
    JDDumpRet(@"+[JDJR_CPUInfo get_cpu_num]", r);
    return r;
}
%end

%hook JDJR_BatteryInfo
+ (id)getBatteryLevel {
    id r = %orig();
    JDDumpRet(@"+[JDJR_BatteryInfo getBatteryLevel]", r);
    return r;
}
+ (id)charing {
    id r = %orig();
    JDDumpRet(@"+[JDJR_BatteryInfo charing]", r);
    return r;
}
+ (id)getBatteryState {
    id r = %orig();
    JDDumpRet(@"+[JDJR_BatteryInfo getBatteryState]", r);
    return r;
}
%end

%hook JDJR_NetInfo
+ (id)networkType {
    id r = %orig();
    JDDumpRet(@"+[JDJR_NetInfo networkType]", r);
    return r;
}
+ (id)getNetworkType {
    id r = %orig();
    JDDumpRet(@"+[JDJR_NetInfo getNetworkType]", r);
    return r;
}
+ (BOOL)isNetListen {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_NetInfo isNetListen]", JDYN(r));
    return r;
}
+ (id)carrierMNC {
    id r = %orig();
    JDDumpRet(@"+[JDJR_NetInfo carrierMNC]", r);
    return r;
}
+ (id)carrierMCC {
    id r = %orig();
    JDDumpRet(@"+[JDJR_NetInfo carrierMCC]", r);
    return r;
}
%end

#pragma mark - 8. DJRiskManager

%hook DJRiskManager
+ (id)sharedManager {
    id r = %orig();
    JDDumpRet(@"+[DJRiskManager sharedManager]", r);
    return r;
}
- (BOOL)isJailbreak {
    BOOL r = %orig();
    JDDumpPrim(@"-[DJRiskManager isJailbreak]", JDYN(r));
    return r;
}
- (id)idfa {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager idfa]", r);
    return r;
}
- (id)idfv {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager idfv]", r);
    return r;
}
- (id)imsi {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager imsi]", r);
    return r;
}
- (id)locationInfo {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager locationInfo]", r);
    return r;
}
- (id)networkType {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager networkType]", r);
    return r;
}
- (void)startTracingFingerprintWithConfig:(id)arg1 {
    JDDumpRet(@"-[DJRiskManager startTracingFingerprintWithConfig:]", arg1);
    %orig(arg1);
}
%end

#pragma mark - 9. GTC / ZX / JCORE

%hook GTCDeviceUtils
+ (BOOL)isJailbreak {
    BOOL r = %orig();
    JDDumpPrim(@"+[GTCDeviceUtils isJailbreak]", JDYN(r));
    return r;
}
+ (BOOL)isUseProxy {
    BOOL r = %orig();
    JDDumpPrim(@"+[GTCDeviceUtils isUseProxy]", JDYN(r));
    return r;
}
+ (BOOL)isDevelopmentEnv {
    BOOL r = %orig();
    JDDumpPrim(@"+[GTCDeviceUtils isDevelopmentEnv]", JDYN(r));
    return r;
}
+ (id)idfa {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils idfa]", r);
    return r;
}
+ (id)idfv {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils idfv]", r);
    return r;
}
+ (id)mymac {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils mymac]", r);
    return r;
}
%end

%hook ZXSDKUtils
+ (BOOL)isJailbreak {
    BOOL r = %orig();
    JDDumpPrim(@"+[ZXSDKUtils isJailbreak]", JDYN(r));
    return r;
}
+ (BOOL)isDevelopmentEnv {
    BOOL r = %orig();
    JDDumpPrim(@"+[ZXSDKUtils isDevelopmentEnv]", JDYN(r));
    return r;
}
+ (id)idfv {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils idfv]", r);
    return r;
}
+ (id)retriveIDFA {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils retriveIDFA]", r);
    return r;
}
%end

%hook JCOREUtilities
+ (BOOL)isJailbroken {
    BOOL r = %orig();
    JDDumpPrim(@"+[JCOREUtilities isJailbroken]", JDYN(r));
    return r;
}
+ (BOOL)amIbeginDeugged {
    BOOL r = %orig();
    JDDumpPrim(@"+[JCOREUtilities amIbeginDeugged]", JDYN(r));
    return r;
}
+ (id)ssid {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities ssid]", r);
    return r;
}
+ (id)macAddress {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities macAddress]", r);
    return r;
}
+ (id)jStringSysctl:(id)arg1 {
    id r = %orig(arg1);
    JDLog(@"+[JCOREUtilities jStringSysctl:] key=%@ ret=%@", JDSafeDesc(arg1), JDSafeDesc(r));
    return r;
}
%end

#pragma mark - 10. GeTui LAN detect

%hook GTCGbdOTDetect
- (void)startWithComplete:(id)arg1 {
    JDLog(@"-[GTCGbdOTDetect startWithComplete:]");
    %orig(arg1);
}
- (void)search {
    JDLog(@"-[GTCGbdOTDetect search]");
    %orig();
}
- (id)getSearchString {
    id r = %orig();
    JDDumpRet(@"-[GTCGbdOTDetect getSearchString]", r);
    return r;
}
%end

%hook GTCGbdPDetect
- (void)startScanningCount:(int)arg1 complete:(id)arg2 {
    JDDumpPrim(@"-[GTCGbdPDetect startScanningCount:complete:]", @(arg1).stringValue);
    %orig(arg1, arg2);
}
%end

%hook GTCMacDetect
- (void)startScanningAllWithMaxCount:(long long)arg1 andPingIsEnable:(BOOL)arg2 {
    JDLog(@"-[GTCMacDetect startScanningAllWithMaxCount:%lld ping:%@]", arg1, JDYN(arg2));
    %orig(arg1, arg2);
}
- (BOOL)startScanningMySelf {
    BOOL r = %orig();
    JDDumpPrim(@"-[GTCMacDetect startScanningMySelf]", JDYN(r));
    return r;
}
%end

#pragma mark - 11. JDGuard

%hook JDGuardLaunchCenter
+ (void)launch {
    JDLog(@"+[JDGuardLaunchCenter launch]");
    %orig();
}
%end

%hook JDGuardModule
+ (id)collectInfo {
    id r = %orig();
    JDDumpRet(@"+[JDGuardModule collectInfo]", r);
    return r;
}
+ (id)fetchJdstInfo {
    id r = %orig();
    JDDumpRet(@"+[JDGuardModule fetchJdstInfo]", r);
    return r;
}
+ (void)reportEvent:(id)arg1 {
    JDDumpRet(@"+[JDGuardModule reportEvent:]", arg1);
    %orig(arg1);
}
%end

%hook JDGuardTaskCenter
- (void)startTask {
    JDLog(@"-[JDGuardTaskCenter startTask]");
    %orig();
}
- (void)runloopScanRisk {
    JDLog(@"-[JDGuardTaskCenter runloopScanRisk]");
    %orig();
}
- (void)runloopReflashPolicy {
    JDLog(@"-[JDGuardTaskCenter runloopReflashPolicy]");
    %orig();
}
%end

%hook JDGuardTask4
- (void)reportEnvInfoWithSubParams:(id)arg1 channel:(int)arg2 forSence:(id)arg3 {
    JDLog(@"-[JDGuardTask4 reportEnvInfo channel=%d scene=%@]", arg2, JDSafeDesc(arg3));
    JDDumpRet(@"JDGuardTask4 reportEnvInfo subParams", arg1);
    %orig(arg1, arg2, arg3);
}
- (void)didUpdateScanInfo:(id)arg1 {
    JDDumpRet(@"-[JDGuardTask4 didUpdateScanInfo:]", arg1);
    %orig(arg1);
}
%end

#pragma mark - 12. Sam business / LAPolicy / Face permission

%hook JDJR_Sam_Business_unique
+ (id)getStgDeviceInfoDic {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Sam_Business_unique getStgDeviceInfoDic]", r);
    return r;
}
+ (id)getCacheTokenByBizId:(id)arg1 pin:(id)arg2 {
    // ✅ 将 pin 改为 arg2
    id r = %orig(arg1, arg2); 
    JDLog(@"+[JDJR_Sam_Business_unique getCacheTokenByBizId:] biz=%@", JDSafeDesc(arg1));
    JDDumpRet(@"getCacheToken RET", r);
    return r;
}
%end



%hook jdcnLAPolicyAuth
+ (id)getDeviceInfo {
    id r = %orig();
    JDDumpRet(@"+[jdcnLAPolicyAuth getDeviceInfo]", r);
    return r;
}
+ (id)JRRiskGetDeviceinfoToServers {
    id r = %orig();
    JDDumpRet(@"+[jdcnLAPolicyAuth JRRiskGetDeviceinfoToServers]", r);
    return r;
}
+ (long long)getBiometryType {
    long long r = %orig();
    JDDumpPrim(@"+[jdcnLAPolicyAuth getBiometryType]", @(r).stringValue);
    return r;
}
+ (id)getBioTypeStr {
    id r = %orig();
    JDDumpRet(@"+[jdcnLAPolicyAuth getBioTypeStr]", r);
    return r;
}
%end

%hook STFTakePhotoAuthorizationCenter
+ (void)checkCameraAuthorization:(id)arg1 error:(id)arg2 {
    JDLog(@"+[STFTakePhotoAuthorizationCenter checkCameraAuthorization:]");
    %orig(arg1, arg2);
}
+ (void)checkPhotoAlbumAuthorization:(id)arg1 error:(id)arg2 {
    JDLog(@"+[STFTakePhotoAuthorizationCenter checkPhotoAlbumAuthorization:]");
    %orig(arg1, arg2);
}
%end

#pragma mark - ctor
// ▼▼▼▼▼ 新增的上报拦截 Hook ▼▼▼▼▼

#pragma mark - JRRisk HTTP 上报

%hook JRRisk_Request
- (id)requestSerializationWithParams:(id)arg1 withConfig:(id)arg2 {
    JDDumpUpload(@"JRRisk_Request requestSerialization params", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"JRRisk_Request requestSerialization RET", r);
    return r;
}
- (void)PostConfigHttpWorking:(id)arg1 BaseUrl:(id)arg2 serviceKey:(id)arg3 parameters:(id)arg4 receiveBackInfo:(id)arg5 {
    JDLog(@"==== UPLOAD JRRisk POST url=%@ serviceKey=%@", JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JRRisk POST parameters", arg4);
    %orig(arg1, arg2, arg3, arg4, arg5);
}
- (void)PostConfigHttpWorking:(id)arg1 BaseUrl:(id)arg2 serviceKey:(id)arg3 header:(id)arg4 parameters:(id)arg5 receiveBackInfo:(id)arg6 {
    JDLog(@"==== UPLOAD JRRisk POST+hdr url=%@ serviceKey=%@", JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JRRisk POST header", arg4);
    JDDumpUpload(@"JRRisk POST parameters", arg5);
    %orig(arg1, arg2, arg3, arg4, arg5, arg6);
}
%end

#pragma mark - JDGuard 网络上报

%hook JDGuardNetworkReq
- (id)initWithUrlPath:(id)arg1 bodyData:(id)arg2 headers:(id)arg3 method:(unsigned long long)arg4 {
    JDLog(@"==== UPLOAD JDGuardNetworkReq url=%@ method=%llu", JDSafeDesc(arg1), arg4);
    JDDumpUpload(@"JDGuardNetworkReq headers", arg3);
    JDDumpUpload(@"JDGuardNetworkReq body", arg2);
    return %orig(arg1, arg2, arg3, arg4);
}
%end

%hook JDGuardNetworkMgr

- (void)_reportInfoWithKeyParam:(id)arg1 serTag:(id)arg2 subParams:(id)arg3 needRetry:(BOOL)arg4 dataTask:(id)arg5 callback:(id)arg6 {
    JDLog(@"==== UPLOAD JDGuard _reportInfo serTag=%@ needRetry=%@", JDSafeDesc(arg2), JDYN(arg4));
    JDDumpUpload(@"JDGuard _reportInfo keyParam", arg1);
    JDDumpUpload(@"JDGuard _reportInfo subParams", arg3);
    %orig(arg1, arg2, arg3, arg4, arg5, arg6);
}

// 【修复 2/5】JDGuardNetworkMgr.fetchConfigInfoWithSubParams:
// 原 selector 缺少 switchForDYNVMP:，真实签名如下：
- (void)fetchConfigInfoWithSubParams:(id)arg1 dataTask:(id)arg2 switchForDYNVMP:(BOOL)arg3 callback:(id)arg4 {
    JDLog(@"==== UPLOAD JDGuard fetchConfig switchForDYNVMP=%@", JDYN(arg3));
    JDDumpUpload(@"JDGuard fetchConfig subParams", arg1);
    %orig(arg1, arg2, arg3, arg4);
}

// 原来那个 "_retry_reportInfoWithKeyParam:subParams:reportVer:dataTask:callback:"
// 在这份头文件里完全找不到对应方法，直接删除，不要保留（避免误导）。

%end

%hook JDGuardJobBase
- (id)jobData {
    id r = %orig();
    JDDumpUpload(@"JDGuardJobBase jobData", r);
    return r;
}
- (void)doJob {
    // 强制转换为 (id)，绕过前向声明限制
    JDLog(@"==== UPLOAD %@ doJob", NSStringFromClass([(id)self class]));
    %orig();
    id rr = nil;
    @try {
        // 强制转换为 (id)
        rr = object_getIvar(self, class_getInstanceVariable([(id)self class], "_reportResult"));
        if (!rr) {
            // 强制转换为 (id)
            rr = [(id)self valueForKey:@"reportResult"];
        }
    } @catch (__unused NSException *e) {
        rr = @"<read failed>";
    }
    JDDumpUpload(@"JDGuardJobBase reportResult", rr);
}
%end


%hook JDGuardInnerRiskJob
- (id)jobData {
    id r = %orig();
    JDDumpUpload(@"JDGuardInnerRiskJob jobData", r);
    return r;
}
- (id)getDnsID {
    id r = %orig();
    JDDumpRet(@"JDGuardInnerRiskJob getDnsID", r);
    return r;
}
%end

%hook JDGuardInnerBasicJob
- (id)jobData {
    id r = %orig();
    JDDumpUpload(@"JDGuardInnerBasicJob jobData", r);
    return r;
}
%end

%hook JDGuardInnerUserJob
- (id)jobData {
    id r = %orig();
    JDDumpUpload(@"JDGuardInnerUserJob jobData", r);
    return r;
}
%end

%hook JDGuardSceneSigJob
- (id)jobData {
    id r = %orig();
    JDDumpUpload(@"JDGuardSceneSigJob jobData", r);
    return r;
}
%end

#pragma mark - Sam 设备/传感器上报

%hook JDJR_Sam_Business_unique
+ (void)asyncReportDevice:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam asyncReportDevice pin=%@", JDSafeDesc(arg2));
    JDDumpUpload(@"Sam asyncReportDevice bizId", arg1);
    %orig(arg1, arg2, arg3);
}
+ (void)reportDeviceDataByBizId:(id)arg1 pin:(id)arg2 sensors:(id)arg3 startTime:(id)arg4 endTime:(id)arg5 completed:(id)arg6 {
    JDLog(@"==== UPLOAD Sam reportDeviceData biz=%@ pin=%@ start=%@ end=%@", JDSafeDesc(arg1), JDSafeDesc(arg2), JDSafeDesc(arg4), JDSafeDesc(arg5));
    JDDumpUpload(@"Sam reportDeviceData sensors", arg3);
    %orig(arg1, arg2, arg3, arg4, arg5, arg6);
}
+ (void)reportRealTimeDataByBizId:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam reportRealTime biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)_reportRealTimeDataByBizId:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam _reportRealTime biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)collectionDs:(id)arg1 pin:(id)arg2 collectionAry:(id)arg3 completed:(id)arg4 {
    JDLog(@"==== UPLOAD Sam collectionDs biz=%@", JDSafeDesc(arg1));
    JDDumpUpload(@"Sam collectionDs collectionAry", arg3);
    %orig(arg1, arg2, arg3, arg4);
}
+ (void)collectionDs2:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam collectionDs2 biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)collectionDs2:(id)arg1 pin:(id)arg2 duraTime:(double)arg3 interval:(double)arg4 completed:(id)arg5 {
    JDLog(@"==== UPLOAD Sam collectionDs2+sensor biz=%@ dura=%f interval=%f", JDSafeDesc(arg1), arg3, arg4);
    %orig(arg1, arg2, arg3, arg4, arg5);
}
+ (void)collectionStg:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam collectionStg biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)collectionTk:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam collectionTk biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)collectionCp:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam collectionCp biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)triggerCollectionDeviceByBizId:(id)arg1 pin:(id)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD Sam triggerCollectionDevice biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
+ (void)getDS2InfoDic:(id)arg1 {
    JDDumpUpload(@"Sam getDS2InfoDic", arg1);
    %orig(arg1);
}
+ (void)judgeGuestWithDeviceInfo:(id)arg1 {
    JDDumpUpload(@"Sam judgeGuestWithDeviceInfo", arg1);
    %orig(arg1);
}
+ (void)collectionDs2ForScreenData:(id)arg1 completed:(id)arg2 {
    JDDumpUpload(@"Sam collectionDs2ForScreenData", arg1);
    %orig(arg1, arg2);
}
+ (void)collectionDs2ForSchemeDataWithBizId:(id)arg1 completed:(id)arg2 {
    JDLog(@"==== UPLOAD Sam collectionDs2ForScheme biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2);
}
%end

%hook JDJR_BiologicalProbeKit
+ (void)getRiskDataByBizId:(id)arg1 pin:(id)arg2 riskType:(int)arg3 completed:(id)arg4 {
    JDLog(@"==== UPLOAD BioProbe getRiskData biz=%@ type=%d", JDSafeDesc(arg1), arg3);
    %orig(arg1, arg2, arg3, arg4);
}
+ (void)triggerCollectionDeviceTypeByBizId:(id)arg1 pin:(id)arg2 {
    JDLog(@"==== UPLOAD BioProbe triggerDevice biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2);
}
+ (void)triggerCollectionSensorTypeByBizId:(id)arg1 pin:(id)arg2 duraTime:(double)arg3 interval:(double)arg4 {
    JDLog(@"==== UPLOAD BioProbe triggerSensor biz=%@ dura=%f interval=%f", JDSafeDesc(arg1), arg3, arg4);
    %orig(arg1, arg2, arg3, arg4);
}
+ (void)new_triggerCollectionDeviceTypeByBizId:(id)arg1 pin:(id)arg2 {
    JDLog(@"==== UPLOAD BioProbe new_triggerDevice biz=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2);
}
%end

%hook JDJR_CoreMotionManager
- (void)uploadData:(id)arg1 withCompletedBlock:(id)arg2 {
    JDDumpUpload(@"JDJR_CoreMotionManager uploadData", arg1);
    %orig(arg1, arg2);
}
- (void)startCollectionForDuraTime:(double)arg1 Interval:(double)arg2 completed:(id)arg3 {
    JDLog(@"==== UPLOAD CoreMotion start dura=%f interval=%f", arg1, arg2);
    %orig(arg1, arg2, arg3);
}
- (void)bgUpload {
    JDLog(@"==== UPLOAD CoreMotion bgUpload");
    %orig();
}
%end

#pragma mark - 挑战风控 JDBRisk

%hook JDBRiskAPI

- (void)checkResultWithParams:(id)arg1 resp:(id)arg2 {
    JDDumpUpload(@"JDBRiskAPI checkResultWithParams", arg1);
    %orig(arg1, arg2);
}

%end

%hook JDBRiskRequestModel
+ (id)analyzeRiskRequestDict:(id)arg1 {
    JDDumpUpload(@"JDBRiskRequestModel analyzeRiskRequestDict", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"JDBRiskRequestModel analyze RET", r);
    return r;
}
%end

%hook JDBRiskHandleManager

- (void)startDisposal:(id)arg1 pageID:(id)arg2 callback:(id)arg3 failedCallback:(id)arg4 {
    JDLog(@"==== UPLOAD JDBRiskHandle startDisposal pageID=%@", JDSafeDesc(arg2));
    JDDumpUpload(@"JDBRiskHandle startDisposal arg1", arg1);
    %orig(arg1, arg2, arg3, arg4);
}

// 【补充 5/5】拿风控二次验证结果 Token 的入口，之前完全没接
- (id)getStdToken {
    id r = %orig();
    JDDumpRet(@"-[JDBRiskHandleManager getStdToken]", r);
    return r;
}

- (void)requestCheckToken:(id)arg1 riskRequest:(id)arg2 sid:(id)arg3 {
    JDDumpUpload(@"JDBRiskHandle requestCheckToken riskRequest", arg2);
    JDLog(@"-[JDBRiskHandleManager requestCheckToken:riskRequest:sid:] sid=%@", JDSafeDesc(arg3));
    %orig(arg1, arg2, arg3);
}

- (void)verifyRiskRequest:(id)arg1 comleteBlock:(id)arg2 {
    JDDumpUpload(@"JDBRiskHandle verifyRiskRequest", arg1);
    %orig(arg1, arg2);
}

%end
#pragma mark - 埋点 / 滑块 / 业务设备上传

%hook JDJR_BuriedPointService
+ (void)postMlogByAttributes:(id)arg1 eventId:(id)arg2 businessId:(id)arg3 {
    JDLog(@"==== UPLOAD BuriedPoint eventId=%@ businessId=%@", JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"BuriedPoint attributes", arg1);
    %orig(arg1, arg2, arg3);
}
%end

%hook JDJR_LegolasNetworkServeice
- (void)postSlideSByScrollPointsByParam:(id)arg1 completed:(id)arg2 {
    JDDumpUpload(@"Legolas postSlideS scrollPoints", arg1);
    %orig(arg1, arg2);
}
- (void)postSlideGByParam:(id)arg1 completed:(id)arg2 {
    JDDumpUpload(@"Legolas postSlideG", arg1);
    %orig(arg1, arg2);
}
%end

%hook _TtC9DadaStaff25STUploadDeviceInfoManager
- (void)upload {
    JDLog(@"==== UPLOAD STUploadDeviceInfoManager upload");
    %orig();
}
- (void)uploadRequest {
    JDLog(@"==== UPLOAD STUploadDeviceInfoManager uploadRequest");
    id cfg = nil;
    @try {
        // 加上 (id) 强转
        cfg = [(id)self valueForKey:@"configDic"];
    } @catch (__unused NSException *e) {
        cfg = nil;
    }
    JDDumpUpload(@"STUploadDeviceInfoManager configDic", cfg);
    %orig();
}
%end

%hook _TtC9DadaStaff14NDDRiskLogTool
+ (void)handleRiskLogWithEvent:(id)arg1 {
    JDDumpUpload(@"NDDRiskLogTool handleRiskLogWithEvent", arg1);
    %orig(arg1);
}
+ (void)fetchConfig {
    JDLog(@"==== UPLOAD NDDRiskLogTool fetchConfig");
    %orig();
}
%end

#pragma mark - 支付宝 APDID / 个推 ZX 上报点

%hook ASSSecurityManager
- (id)getApdidToken:(id)arg1 {
    JDDumpUpload(@"ASSSecurityManager getApdidToken ARG", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"ASSSecurityManager getApdidToken RET", r);
    return r;
}
- (id)getApdidResult:(id)arg1 {
    JDDumpUpload(@"ASSSecurityManager getApdidResult ARG", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"ASSSecurityManager getApdidResult RET", r);
    return r;
}
- (void)initializeSecuritySDKTask:(id)arg1 {
    JDDumpUpload(@"ASSSecurityManager initializeSecuritySDKTask", arg1);
    %orig(arg1);
}
%end

%hook AppDelegate
- (void)uploadFingerprint {
    JDLog(@"==== UPLOAD AppDelegate uploadFingerprint");
    %orig();
}
%end

// ▲▲▲▲▲ 新增的上报拦截 Hook 结束 ▲▲▲▲▲
#pragma mark - 13. DJRiskManager 补充：定位回调 / 设备身份 / ATT 授权

%hook DJRiskManager

- (void)updateLocation {
    JDLog(@"-[DJRiskManager updateLocation] 被调用");
    %orig();
}

// 真正拿到实时经纬度的地方：CLLocationManagerDelegate 回调
- (void)locationManager:(id)arg1 didUpdateLocations:(id)arg2 {
    JDDumpUpload(@"DJRiskManager locationManager:didUpdateLocations:", arg2);
    %orig(arg1, arg2);
}

- (void)locationManager:(id)arg1 didFailWithError:(id)arg2 {
    JDLog(@"-[DJRiskManager locationManager:didFailWithError:] error=%@", JDSafeDesc(arg2));
    %orig(arg1, arg2);
}

- (void)locationManager:(id)arg1 didChangeAuthorizationStatus:(int)arg2 {
    JDDumpPrim(@"-[DJRiskManager locationManager:didChangeAuthorizationStatus:]", @(arg2).stringValue);
    %orig(arg1, arg2);
}

- (unsigned long long)trackingAuthorizationStatus {
    unsigned long long r = %orig();
    JDDumpPrim(@"-[DJRiskManager trackingAuthorizationStatus]", @(r).stringValue);
    return r;
}

- (void)requestTrackingAuthorizationWithCompletionHandler:(id)arg1 {
    JDLog(@"-[DJRiskManager requestTrackingAuthorizationWithCompletionHandler:] 被调用（ATT 弹窗触发点）");
    %orig(arg1);
}

- (id)deviceModel {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager deviceModel]", r);
    return r;
}

- (id)deviceName {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager deviceName]", r);
    return r;
}

- (id)systemVersion {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager systemVersion]", r);
    return r;
}

- (id)sdkVersion {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager sdkVersion]", r);
    return r;
}

- (int)appPlatform {
    int r = %orig();
    JDDumpPrim(@"-[DJRiskManager appPlatform]", @(r).stringValue);
    return r;
}

- (id)screenResolution {
    id r = %orig();
    JDDumpRet(@"-[DJRiskManager screenResolution]", r);
    return r;
}

%end


#pragma mark - 14. JCOREUtilities 补充：加密原语 / 持久化设备ID / 系统信息

%hook JCOREUtilities

// 加密原语：能直接拿到加密前明文 + 用的 key/iv，是破解上传密文内容的关键入口
+ (id)aes256EncryptData:(id)arg1 withKey:(id)arg2 iv:(const char *)arg3 {
    JDDumpRet(@"+[JCOREUtilities aes256EncryptData:] PLAINTEXT", arg1);
    JDDumpRet(@"+[JCOREUtilities aes256EncryptData:] KEY", arg2);
    JDLog(@"+[JCOREUtilities aes256EncryptData:] iv=%@", arg3 ? [NSString stringWithUTF8String:arg3] : @"(null)");
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"+[JCOREUtilities aes256EncryptData:] CIPHERTEXT", r);
    return r;
}

+ (id)aesEncryptData:(id)arg1 withKey:(id)arg2 iv:(const char *)arg3 {
    JDDumpRet(@"+[JCOREUtilities aesEncryptData:] PLAINTEXT", arg1);
    JDDumpRet(@"+[JCOREUtilities aesEncryptData:] KEY", arg2);
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"+[JCOREUtilities aesEncryptData:] CIPHERTEXT", r);
    return r;
}

+ (id)aesDecryptData:(id)arg1 withKey:(id)arg2 iv:(const char *)arg3 {
    JDDumpRet(@"+[JCOREUtilities aesDecryptData:] INPUT_CIPHERTEXT", arg1);
    JDDumpRet(@"+[JCOREUtilities aesDecryptData:] KEY", arg2);
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"+[JCOREUtilities aesDecryptData:] PLAINTEXT_OUT", r);
    return r;
}

+ (id)rsaEncrypt:(id)arg1 publicKey:(id)arg2 {
    JDDumpRet(@"+[JCOREUtilities rsaEncrypt:] PLAINTEXT", arg1);
    JDDumpRet(@"+[JCOREUtilities rsaEncrypt:] PUBLIC_KEY", arg2);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JCOREUtilities rsaEncrypt:] CIPHERTEXT", r);
    return r;
}

+ (id)encryptKeyForHttp {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities encryptKeyForHttp]", r);
    return r;
}

// 持久化设备标识相关
+ (id)deviceMacAddress {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities deviceMacAddress]", r);
    return r;
}

+ (id)fakeIMEI {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities fakeIMEI]", r);
    return r;
}

+ (id)createDeviceIdWithKey:(id)arg1 {
    JDLog(@"+[JCOREUtilities createDeviceIdWithKey:] key=%@", JDSafeDesc(arg1));
    id r = %orig(arg1);
    JDDumpRet(@"+[JCOREUtilities createDeviceIdWithKey:] RET", r);
    return r;
}

+ (id)deviceID:(id)arg1 {
    id r = %orig(arg1);
    JDDumpRet(@"+[JCOREUtilities deviceID:]", r);
    return r;
}

+ (id)oldDeviceID {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities oldDeviceID]", r);
    return r;
}

// 系统/机型/网络辅助信息
+ (id)telephonyInfo {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities telephonyInfo]", r);
    return r;
}

+ (id)ctCarrierInfo {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities ctCarrierInfo]", r);
    return r;
}

+ (id)systemName {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities systemName]", r);
    return r;
}

+ (id)model {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities model]", r);
    return r;
}

+ (id)modelName {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities modelName]", r);
    return r;
}

+ (id)bundleID {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities bundleID]", r);
    return r;
}

+ (id)currentResolution {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities currentResolution]", r);
    return r;
}

+ (BOOL)isAccessWifiInfo {
    BOOL r = %orig();
    JDDumpPrim(@"+[JCOREUtilities isAccessWifiInfo]", JDYN(r));
    return r;
}

+ (id)kernelVersion {
    id r = %orig();
    JDDumpRet(@"+[JCOREUtilities kernelVersion]", r);
    return r;
}

%end


#pragma mark - 15. GTCDeviceUtils / ZXSDKUtils 补充标识符

%hook GTCDeviceUtils

+ (id)deviceTokenForPush {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils deviceTokenForPush]", r);
    return r;
}

+ (long long)simType {
    long long r = %orig();
    JDDumpPrim(@"+[GTCDeviceUtils simType]", @(r).stringValue);
    return r;
}

+ (id)ISPName {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils ISPName]", r);
    return r;
}

+ (id)retriveDeviceId {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils retriveDeviceId]", r);
    return r;
}

+ (id)currentCountryCode {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils currentCountryCode]", r);
    return r;
}

+ (id)ramMemorySize {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils ramMemorySize]", r);
    return r;
}

+ (id)diskInfo {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils diskInfo]", r);
    return r;
}

+ (id)networkflowInfo {
    id r = %orig();
    JDDumpRet(@"+[GTCDeviceUtils networkflowInfo]", r);
    return r;
}

%end

%hook ZXSDKUtils

+ (id)zxAppId {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils zxAppId]", r);
    return r;
}

+ (id)channelId {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils channelId]", r);
    return r;
}

+ (id)encyptBody:(id)arg1 {
    JDDumpRet(@"+[ZXSDKUtils encyptBody:] INPUT", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[ZXSDKUtils encyptBody:] OUTPUT", r);
    return r;
}

+ (id)retriveIDFAString {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils retriveIDFAString]", r);
    return r;
}

+ (id)apnsInfo {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils apnsInfo]", r);
    return r;
}

+ (id)locationDescription {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils locationDescription]", r);
    return r;
}

+ (id)getDeviceIpd {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils getDeviceIpd]", r);
    return r;
}

+ (id)getAnpiIpd {
    id r = %orig();
    JDDumpRet(@"+[ZXSDKUtils getAnpiIpd]", r);
    return r;
}

%end


#pragma mark - 16. JDJR_DeviceInfo 补充：NFC / 生物识别 / 基础信息

%hook JDJR_DeviceInfo

+ (id)aNumStr {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo aNumStr]", r);
    return r;
}

+ (id)orientation {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo orientation]", r);
    return r;
}

+ (id)systemName {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo systemName]", r);
    return r;
}

+ (id)installTime {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo installTime]", r);
    return r;
}

+ (BOOL)isFaceNFC {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_DeviceInfo isFaceNFC]", JDYN(r));
    return r;
}

+ (BOOL)appWithNFC {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJR_DeviceInfo appWithNFC]", JDYN(r));
    return r;
}

+ (BOOL)NFCFromClass:(id)arg1 {
    BOOL r = %orig(arg1);
    JDLog(@"+[JDJR_DeviceInfo NFCFromClass:] arg=%@ ret=%@", JDSafeDesc(arg1), JDYN(r));
    return r;
}

+ (BOOL)isITouchWithBioTypeCallBack:(id)arg1 {
    JDLog(@"+[JDJR_DeviceInfo isITouchWithBioTypeCallBack:] 被调用（TouchID/FaceID 能力探测）");
    BOOL r = %orig(arg1);
    return r;
}

+ (id)getResolution {
    id r = %orig();
    JDDumpRet(@"+[JDJR_DeviceInfo getResolution]", r);
    return r;
}

%end


#pragma mark - 17. JDJR_HardwareInfo 补充：生物识别配置 / 运营商辅助方法

%hook JDJR_HardwareInfo

- (id)touchID {
    id r = %orig();
    JDDumpRet(@"-[JDJR_HardwareInfo touchID]", r);
    return r;
}

- (void)configIosBioType:(id)arg1 {
    JDDumpRet(@"-[JDJR_HardwareInfo configIosBioType:] ARG", arg1);
    %orig(arg1);
}

- (void)generateCaId {
    JDLog(@"-[JDJR_HardwareInfo generateCaId] 被调用（与上传数据的加密证书ID相关）");
    %orig();
}

- (id)myCarrier {
    id r = %orig();
    JDDumpRet(@"-[JDJR_HardwareInfo myCarrier]", r);
    return r;
}



%end


#pragma mark - 18. 局域网设备扫描（GTCGbdOTDetect / GTCGbdPDetect）

%hook GTCGbdOTDetect

- (void)judgeDeviceWithData:(id)arg1 {
    JDDumpUpload(@"GTCGbdOTDetect judgeDeviceWithData", arg1);
    %orig(arg1);
}

%end

%hook GTCGbdPDetect

- (id)getHaForKey:(id)arg1 {
    id r = %orig(arg1);
    JDLog(@"-[GTCGbdPDetect getHaForKey:] key=%@ ret=%@", JDSafeDesc(arg1), JDSafeDesc(r));
    return r;
}

- (void)updateOnline:(id)arg1 {
    JDDumpUpload(@"GTCGbdPDetect updateOnline(发现的局域网设备)", arg1);
    %orig(arg1);
}

%end


#pragma mark - 19. JDGuardModule：初始化密钥 / 请求签名机制

%hook JDGuardModule

+ (void)configAppKey:(id)arg1 eid:(id)arg2 logo:(id)arg3 pwdTable:(id)arg4 {
    JDLog(@"+[JDGuardModule configAppKey:eid:logo:pwdTable:] appKey=%@ eid=%@ logo=%@", JDSafeDesc(arg1), JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpRet(@"JDGuardModule configAppKey pwdTable", arg4);
    %orig(arg1, arg2, arg3, arg4);
}

+ (id)signWithUrlString:(id)arg1 contentType:(id)arg2 method:(id)arg3 bodyData:(id)arg4 uppercaseBD:(BOOL)arg5 {
    JDLog(@"+[JDGuardModule signWithUrlString:...uppercaseBD:] url=%@ contentType=%@ method=%@", JDSafeDesc(arg1), JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JDGuardModule sign bodyData", arg4);
    id r = %orig(arg1, arg2, arg3, arg4, arg5);
    JDDumpRet(@"JDGuardModule sign RESULT", r);
    return r;
}

+ (id)signWithUrlString:(id)arg1 contentType:(id)arg2 method:(id)arg3 bodyData:(id)arg4 {
    JDLog(@"+[JDGuardModule signWithUrlString:...] url=%@ contentType=%@ method=%@", JDSafeDesc(arg1), JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JDGuardModule sign(no-uppercase) bodyData", arg4);
    id r = %orig(arg1, arg2, arg3, arg4);
    JDDumpRet(@"JDGuardModule sign(no-uppercase) RESULT", r);
    return r;
}

+ (long long)invokeSecurityEventWithName:(id)arg1 extParams:(id)arg2 {
    JDLog(@"+[JDGuardModule invokeSecurityEventWithName:] name=%@", JDSafeDesc(arg1));
    JDDumpRet(@"JDGuardModule invokeSecurityEvent extParams", arg2);
    long long r = %orig(arg1, arg2);
    JDDumpPrim(@"+[JDGuardModule invokeSecurityEventWithName:] RET", @(r).stringValue);
    return r;
}

+ (long long)checkWithUrl:(id)arg1 ref:(id)arg2 sence:(unsigned long long)arg3 senceStr:(id)arg4 {
    long long r = %orig(arg1, arg2, arg3, arg4);
    JDLog(@"+[JDGuardModule checkWithUrl:ref:sence:senceStr:] url=%@ sence=%llu senceStr=%@ ret=%lld", JDSafeDesc(arg1), arg3, JDSafeDesc(arg4), r);
    return r;
}

%end


#pragma mark - 20. JDGuardTask4 补充

%hook JDGuardTask4

- (void)startWorkWithSence:(id)arg1 {
    JDLog(@"-[JDGuardTask4 startWorkWithSence:] sence=%@", JDSafeDesc(arg1));
    %orig(arg1);
}

- (void)didUpdateReportInfoWithSvrtk:(id)arg1 {
    JDDumpUpload(@"JDGuardTask4 didUpdateReportInfoWithSvrtk", arg1);
    %orig(arg1);
}

- (void)didUpdateReportInfoWithUMT:(id)arg1 fromSence:(id)arg2 {
    JDLog(@"-[JDGuardTask4 didUpdateReportInfoWithUMT:fromSence:] sence=%@", JDSafeDesc(arg2));
    JDDumpUpload(@"JDGuardTask4 didUpdateReportInfoWithUMT", arg1);
    %orig(arg1, arg2);
}

- (void)startMonitor {
    JDLog(@"-[JDGuardTask4 startMonitor]");
    %orig();
}

%end


#pragma mark - 21. jdcnLAPolicyAuth：生物认证触发风控二次验证

%hook jdcnLAPolicyAuth

+ (void)buriedWithParams:(id)arg1 {
    JDDumpUpload(@"jdcnLAPolicyAuth buriedWithParams", arg1);
    %orig(arg1);
}

+ (id)ChangesdkVerifyIdIfNoCreateIt {
    id r = %orig();
    JDDumpRet(@"+[jdcnLAPolicyAuth ChangesdkVerifyIdIfNoCreateIt]", r);
    return r;
}

+ (void)evaluatePolicy:(unsigned long long)arg1 localizedCancelTitle:(id)arg2 localizedFallbackTitle:(id)arg3 localizedDetailDescribe:(id)arg4 riskVerfyidentify:(id)arg5 callBackResult:(id)arg6 {
    JDLog(@"==== UPLOAD jdcnLAPolicyAuth evaluatePolicy policy=%llu riskVerfyidentify=%@ detail=%@", arg1, JDSafeDesc(arg5), JDSafeDesc(arg4));
    %orig(arg1, arg2, arg3, arg4, arg5, arg6);
}

%end


#pragma mark - 22. JDJR_Biological_CacheManager：凯撒密码解码器 / 截屏检测 / Keychain持久化ID / 视图层级探测






#pragma mark - 24. JDJR_Motions：传感器原始读数的直接入口（比批量上传更底层）

%hook JDJR_Motions

+ (id)magnetometer {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Motions magnetometer]", r);
    return r;
}

+ (id)gravity {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Motions gravity]", r);
    return r;
}

+ (id)acceleration {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Motions acceleration]", r);
    return r;
}

%end


#pragma mark - 25. JDJR_Biological_BuryingPoint：补充埋点方法


#pragma mark - 26. 抓包环境诊断：SSL 证书锁定 / HttpDNS 防劫持
// 说明：以下两个 hook 全部是「只读记录」——只是在 %orig() 前后打日志，
// 不修改任何参数、不改写返回值，证书校验该通过就通过、该失败就失败，
// 跟 App 本来的判断结果完全一致，只是把这个判断过程和结果记下来给你看。

%hook JDJRSecurityPolicy

// evaluateServerTrust:forDomain: 就是证书锁定(SSL Pinning)真正做比对的地方。
// 抓包工具用自己的证书顶替真实证书时，如果这里返回 NO，
// 就会导致该域名下所有 HTTPS 请求握手失败，App 表现出来往往就是"无网络连接"。
- (BOOL)evaluateServerTrust:(struct __SecTrust *)arg1 forDomain:(id)arg2 {
    BOOL r = %orig(arg1, arg2);
    JDLog(@"-[JDJRSecurityPolicy evaluateServerTrust:forDomain:] domain=%@ trust=%p 结果=%@",
          JDSafeDesc(arg2), arg1, JDYN(r));
    return r;
}

%end


%hook JDJRHttpDNSManager

// HttpDNS 直连服务器真实 IP，绕开系统 DNS——如果系统开了全局代理，
// 这条直连路径可能被代理强制接管而失败，也会表现成"无网络"。
// arg2 是 NSURLAuthenticationChallenge，能看到是对哪个 host 发起的挑战。
- (void)URLSession:(id)arg1 didReceiveChallenge:(id)arg2 completionHandler:(id)arg3 {
    JDDumpRet(@"-[JDJRHttpDNSManager URLSession:didReceiveChallenge:] challenge", arg2);
    %orig(arg1, arg2, arg3);
}

%end
#pragma mark - 28. ASSSecurityManager 补充：阿里UTDID / 信任数据缓存

%hook ASSSecurityManager

+ (id)getUtdid {
    id r = %orig();
    JDDumpRet(@"+[ASSSecurityManager getUtdid]", r);
    return r;
}

+ (id)getTid {
    id r = %orig();
    JDDumpRet(@"+[ASSSecurityManager getTid]", r);
    return r;
}

- (void)updateApdidAndToken:(id)arg1 {
    JDDumpUpload(@"ASSSecurityManager updateApdidAndToken", arg1);
    %orig(arg1);
}

- (BOOL)checkIfTodayFirst {
    BOOL r = %orig();
    JDDumpPrim(@"-[ASSSecurityManager checkIfTodayFirst]", JDYN(r));
    return r;
}

- (id)loadTrustData {
    id r = %orig();
    JDDumpRet(@"-[ASSSecurityManager loadTrustData]", r);
    return r;
}

- (void)saveTrustData:(id)arg1 {
    JDDumpUpload(@"ASSSecurityManager saveTrustData", arg1);
    %orig(arg1);
}

%end


#pragma mark - 29. JDGuardNetworkMgr 补充：错误/事件/告警上报 · 升级检测 · 策略下载

%hook JDGuardNetworkMgr

- (void)reportErrInfoWithParams:(id)arg1 dataTask:(id)arg2 callback:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr reportErrInfo ====");
    JDDumpUpload(@"JDGuardNetworkMgr reportErrInfo params", arg1);
    %orig(arg1, arg2, arg3);
}

- (void)reportEventInfoWithParams:(id)arg1 forEvent:(id)arg2 dataTask:(id)arg3 callback:(id)arg4 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr reportEventInfo forEvent=%@", JDSafeDesc(arg2));
    JDDumpUpload(@"JDGuardNetworkMgr reportEventInfo params", arg1);
    %orig(arg1, arg2, arg3, arg4);
}

- (void)JDWGuard_reportAlertInfoWithParams:(id)arg1 dataTask:(id)arg2 callback:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr JDWGuard_reportAlertInfo ====");
    JDDumpUpload(@"JDGuardNetworkMgr JDWGuard_reportAlertInfo params", arg1);
    %orig(arg1, arg2, arg3);
}

- (void)fetchUpgradeInfoWithSubParams:(id)arg1 dataTask:(id)arg2 callback:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr fetchUpgradeInfo ====");
    JDDumpUpload(@"JDGuardNetworkMgr fetchUpgradeInfo subParams", arg1);
    %orig(arg1, arg2, arg3);
}

- (void)downloadPolicyData:(id)arg1 dataTask:(id)arg2 callback:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr downloadPolicyData ====");
    JDDumpUpload(@"JDGuardNetworkMgr downloadPolicyData ARG", arg1);
    %orig(arg1, arg2, arg3);
}

- (void)JDWGuard_downloadPolicyDataWithCdn:(id)arg1 dataTask:(id)arg2 callback:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardNetworkMgr JDWGuard_downloadPolicyDataWithCdn url/cdn=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}
- (id)baseUrl {
    id r = %orig();
    NSLog(@"[JDEnvAudit] Guard baseUrl=%@", r);
    return r;
}
- (id)getApiUrlWithPath:(id)path {
    id r = %orig();
    NSLog(@"[JDEnvAudit] Guard apiUrl path=%@ -> %@", path, r);
    return r;
}
%end



#pragma mark - 27. JDGuard 策略/配置下发机制：验证是否由服务端远程控制检测清单

%hook JDGuardConfigMgr

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDGuardConfigMgr sharedInstance]", r);
    return r;
}

- (void)startWork {
    JDLog(@"-[JDGuardConfigMgr startWork] 被调用");
    %orig();
}

- (void)didUpdateConfigInfoWithLaunchid:(id)arg1 {
    JDLog(@"-[JDGuardConfigMgr didUpdateConfigInfoWithLaunchid:] launchid=%@", JDSafeDesc(arg1));
    %orig(arg1);
}

- (long long)loadConfigInfoPver {
    long long r = %orig();
    JDDumpPrim(@"-[JDGuardConfigMgr loadConfigInfoPver]", @(r).stringValue);
    return r;
}

- (long long)loadConfigInfoEver {
    long long r = %orig();
    JDDumpPrim(@"-[JDGuardConfigMgr loadConfigInfoEver]", @(r).stringValue);
    return r;
}

- (long long)loadConfigInfoCver {
    long long r = %orig();
    JDDumpPrim(@"-[JDGuardConfigMgr loadConfigInfoCver]", @(r).stringValue);
    return r;
}

%end


%hook JDGuardConfigModel

// invokeList：服务端认为这次应该执行的任务/检测清单
- (void)setInvokeList:(id)arg1 {
    JDDumpUpload(@"JDGuardConfigModel setInvokeList（允许执行的检测清单）", arg1);
    %orig(arg1);
}

// terminationInvokeDic：从命名看，是被服务端明确叫停、不执行的检测清单——
// 这个字段的实际内容极可能直接解释"为什么某次会话越狱检测集体消失"
- (void)setTerminationInvokeDic:(id)arg1 {
    JDDumpUpload(@"JDGuardConfigModel setTerminationInvokeDic（被服务端叫停的检测清单）", arg1);
    %orig(arg1);
}

- (void)setRollBack:(id)arg1 {
    JDDumpRet(@"-[JDGuardConfigModel setRollBack:]（回滚模式配置）", arg1);
    %orig(arg1);
}

- (void)setSplit:(long long)arg1 {
    JDDumpPrim(@"-[JDGuardConfigModel setSplit:]（A/B灰度分组编号）", @(arg1).stringValue);
    %orig(arg1);
}

- (void)setUpdateInterval:(long long)arg1 {
    JDDumpPrim(@"-[JDGuardConfigModel setUpdateInterval:]（策略刷新间隔,单位推测为秒）", @(arg1).stringValue);
    %orig(arg1);
}

- (void)setLaunchid:(id)arg1 {
    JDLog(@"-[JDGuardConfigModel setLaunchid:] launchid=%@", JDSafeDesc(arg1));
    %orig(arg1);
}

%end


%hook JDGuardPolicyMgr

+ (id)sharedManager {
    id r = %orig();
    JDDumpRet(@"+[JDGuardPolicyMgr sharedManager]", r);
    return r;
}

- (void)loadPolicysInfo {
    JDLog(@"-[JDGuardPolicyMgr loadPolicysInfo] 被调用（读取本地已缓存的策略）");
    %orig();
}

- (void)_storePolicysInfo:(id)arg1 {
    JDDumpUpload(@"JDGuardPolicyMgr _storePolicysInfo（服务端下发/写入本地的策略字典）", arg1);
    %orig(arg1);
}

- (void)downloadPolicyModels:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDGuardPolicyMgr downloadPolicyModels ARG", arg1);
    %orig(arg1, arg2);
}

- (void)tryDownloadPolicyModel:(id)arg1 {
    JDDumpRet(@"JDGuardPolicyMgr tryDownloadPolicyModel ARG", arg1);
    %orig(arg1);
}

- (void)updateLocalPolicyDefinition:(id)arg1 needSave:(BOOL)arg2 {
    JDLog(@"-[JDGuardPolicyMgr updateLocalPolicyDefinition:needSave:] needSave=%@", JDYN(arg2));
    JDDumpRet(@"JDGuardPolicyMgr updateLocalPolicyDefinition ARG", arg1);
    %orig(arg1, arg2);
}

%end


%hook JDGuardPolicyModel

- (void)setPolicy_index:(id)arg1 {
    JDLog(@"-[JDGuardPolicyModel setPolicy_index:] %@", JDSafeDesc(arg1));
    %orig(arg1);
}

- (void)setRuleName:(id)arg1 {
    JDLog(@"-[JDGuardPolicyModel setRuleName:] ruleName=%@", JDSafeDesc(arg1));
    %orig(arg1);
}

- (void)setState:(id)arg1 {
    JDLog(@"-[JDGuardPolicyModel setState:] state=%@（该条策略是启用还是禁用)", JDSafeDesc(arg1));
    %orig(arg1);
}

// opcodeValue：不是普通配置，是服务端下发的可执行策略字节码本体
- (void)setOpcodeValue:(id)arg1 {
    JDDumpUpload(@"JDGuardPolicyModel setOpcodeValue（下发的策略字节码原始内容）", arg1);
    %orig(arg1);
}

%end
#pragma mark - 30. 推送唤醒诊断：静默推送 / 个推透传消息

%hook AppDelegate

- (void)application:(id)arg1 didReceiveRemoteNotification:(id)arg2 fetchCompletionHandler:(id)arg3 {
    JDLog(@"==== UPLOAD AppDelegate application:didReceiveRemoteNotification:fetchCompletionHandler: 收到静默推送 ====");
    JDDumpRet(@"AppDelegate 静默推送payload", arg2);
    %orig(arg1, arg2, arg3);
}

- (void)checkProcessNotificationWithApplicationState:(long long)arg1 remoteNotification:(id)arg2 firstLunch:(BOOL)arg3 {
    JDLog(@"-[AppDelegate checkProcessNotificationWithApplicationState:remoteNotification:firstLunch:] appState=%lld firstLunch=%@", arg1, JDYN(arg3));
    JDDumpRet(@"checkProcessNotification remoteNotification内容", arg2);
    %orig(arg1, arg2, arg3);
}

- (void)handleApplicationState:(long long)arg1 didReceiveRemoteNotification:(id)arg2 {
    JDLog(@"-[AppDelegate handleApplicationState:didReceiveRemoteNotification:] appState=%lld", arg1);
    JDDumpRet(@"handleApplicationState remoteNotification内容", arg2);
    %orig(arg1, arg2);
}

- (void)inactive_handleRemoteNotification:(id)arg1 {
    JDLog(@"-[AppDelegate inactive_handleRemoteNotification:] 被调用（App处于inactive状态时收到推送）");
    JDDumpRet(@"inactive_handleRemoteNotification 内容", arg1);
    %orig(arg1);
}

%end


%hook GtSdkManager

// 个推"透传消息"：推送内容可以是任意原始数据，不是用户可见通知
- (void)GXPushManagerDidReceivePayloadData:(id)arg1 taskId:(id)arg2 msgId:(id)arg3 offLine:(BOOL)arg4 appId:(id)arg5 {
    JDLog(@"==== UPLOAD GtSdkManager GXPushManagerDidReceivePayloadData 收到个推透传消息 taskId=%@ msgId=%@ offLine=%@ ====", JDSafeDesc(arg2), JDSafeDesc(arg3), JDYN(arg4));
    JDDumpUpload(@"个推透传消息原始内容", arg1);
    %orig(arg1, arg2, arg3, arg4, arg5);
}

- (void)Getui_didReceiveRemoteNotificationInner:(id)arg1 fetchCompletionHandler:(id)arg2 {
    JDLog(@"-[GtSdkManager Getui_didReceiveRemoteNotificationInner:fetchCompletionHandler:] 被调用");
    JDDumpRet(@"Getui静默推送内部处理payload", arg1);
    %orig(arg1, arg2);
}

- (void)Getui_handleDeviceToken:(id)arg1 {
    JDDumpRet(@"-[GtSdkManager Getui_handleDeviceToken:]", arg1);
    %orig(arg1);
}

%end
#pragma mark - 31. color.imdada.cn 真正的签名/加密实现（可能是sign的真正来源）

%hook NDDColorSignAndEncryptManager_OC

+ (id)encryptData:(id)arg1 {
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC encryptData:] 明文输入", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC encryptData:] 密文输出", r);
    return r;
}

+ (id)hmac:(id)arg1 withKey:(id)arg2 {
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmac:] 明文", arg1);
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmac:withKey:] KEY(疑似加签盐值)", arg2);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmac:] 结果", r);
    return r;
}

+ (id)hmacSha256:(id)arg1 withKey:(id)arg2 {
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmacSha256:] 明文", arg1);
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmacSha256:withKey:] KEY(疑似加签盐值)", arg2);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[NDDColorSignAndEncryptManager_OC hmacSha256:] 结果(应该就是sign值)", r);
    return r;
}

%end





#pragma mark - 33. JDGuardRollBackMode：配置回滚模式的版本号


#pragma mark - 37. JDGuardEventMgr：全局终止开关 + 本地错误缓存（很可能是jdgs错误码最终去处）




#pragma mark - 38. JDGuardUpgradeMgr：升级检测管理器


#pragma mark - 39. JDBLBSCheckFakeUtil：假GPS/虚拟定位检测（直接对应Relocate.dylib这类插件）



#pragma mark - 40. JRRisk_AES / RSA / Sha_XX：sdkfp.jd.com通道自己的加密原语








#pragma mark - 41. JDBRiskColorNetWork：又一套独立的"Color"业务网关客户端（金融风控线自己的）




#pragma mark - 45. JDBJMACollectionHandler：越狱/开挂检测相关的采集字段(从150+个方法里精选)

%hook JDBJMACollectionHandler

+ (id)clIsJailBreak:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clIsJailBreak:] key=%@ value=%@", JDSafeDesc(arg2), JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clIsJailBreakForGetInfo:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clIsJailBreakForGetInfo:] key=%@ value=%@", JDSafeDesc(arg2), JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clIsRoot:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clIsRoot:] key=%@ value=%@", JDSafeDesc(arg2), JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clInsertDylibs:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clInsertDylibs:] value=%@（注入动态库清单，实际类型未知，仅浅层记录避免深挖崩溃）", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clThreadDylib:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDDumpRet(@"+[JDBJMACollectionHandler clThreadDylib:]（线程注入动态库检测）", arg1);
    return %orig(arg1, arg2, arg3);
}

+ (id)clVmpCode:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clVmpCode:] value=%@（虚拟机保护/反篡改代码）", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clAtf:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clAtf:] value=%@", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clPif:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clPif:] value=%@", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clDebug:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clDebug:] value=%@", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clIsVPNConnected:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clIsVPNConnected:] value=%@", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

+ (id)clOpRiderApps:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDDumpRet(@"+[JDBJMACollectionHandler clOpRiderApps:]（检测同类骑手/竞品接单App是否安装）", arg1);
    return %orig(arg1, arg2, arg3);
}

+ (id)clAppList:(id)arg1 forKeys:(id)arg2 intoDict:(id)arg3 {
    JDDumpRet(@"+[JDBJMACollectionHandler clAppList:]（已安装应用清单）", arg1);
    return %orig(arg1, arg2, arg3);
}

+ (id)clJSCore:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 fromFix:(BOOL)arg4 {
    JDLog(@"+[JDBJMACollectionHandler clJSCore:] value=%@ fromFix=%@（JS引擎注入检测）", JDSafeDesc(arg1), JDYN(arg4));
    return %orig(arg1, arg2, arg3, arg4);
}

+ (id)clLastSnapshotPageName:(id)arg1 forKey:(id)arg2 intoDict:(id)arg3 {
    JDLog(@"+[JDBJMACollectionHandler clLastSnapshotPageName:] value=%@（最后一次截屏所在页面）", JDSafeDesc(arg1));
    return %orig(arg1, arg2, arg3);
}

%end



#pragma mark - 47. JDBSafeIPManager / QNHijackingDetectWrapper：网络劫持/安全IP检测





#pragma mark - 48. JDBRandomOpenUDIDManager：openudid生成源头




#pragma mark - 49. JDBLBSReportManager：假GPS检测结果真正的上报出口


// ============================================================
// 【第1部分】完整独立、未被触碰的风控体系（京东金融/白条线）
// ============================================================

%hook JDBGuardModule

+ (id)collectInfo {
    id r = %orig();
    JDDumpRet(@"+[JDBGuardModule collectInfo]", r);
    return r;
}

+ (BOOL)enforcement {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDBGuardModule enforcement]", JDYN(r));
    return r;
}

+ (void)reportEvent:(id)arg1 {
    JDLog(@"==== UPLOAD JDBGuardModule reportEvent ====");
    JDDumpUpload(@"JDBGuardModule reportEvent 内容", arg1);
    %orig(arg1);
}

+ (id)fetchDLBInfo {
    id r = %orig();
    JDDumpRet(@"+[JDBGuardModule fetchDLBInfo]", r);
    return r;
}

+ (id)decryptData:(id)arg1 {
    JDDumpRet(@"+[JDBGuardModule decryptData:] 输入密文", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[JDBGuardModule decryptData:] 解密后明文", r);
    return r;
}

+ (id)encryptData:(id)arg1 {
    JDDumpRet(@"+[JDBGuardModule encryptData:] 明文输入", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[JDBGuardModule encryptData:] 密文输出", r);
    return r;
}

+ (void)configEidCallback:(id)arg1 {
    JDLog(@"+[JDBGuardModule configEidCallback:] 被调用");
    %orig(arg1);
}

+ (void)configA2Callback:(id)arg1 {
    JDLog(@"+[JDBGuardModule configA2Callback:] 被调用");
    %orig(arg1);
}

+ (void)configPinCallback:(id)arg1 {
    JDLog(@"+[JDBGuardModule configPinCallback:] 被调用");
    %orig(arg1);
}

+ (void)configLocationCallback:(id)arg1 {
    JDLog(@"+[JDBGuardModule configLocationCallback:] 被调用");
    %orig(arg1);
}

+ (long long)checkWithUrl:(id)arg1 ref:(id)arg2 sence:(unsigned long long)arg3 senceStr:(id)arg4 {
    long long r = %orig(arg1, arg2, arg3, arg4);
    JDLog(@"+[JDBGuardModule checkWithUrl:ref:sence:senceStr:] url=%@ sence=%llu ret=%lld", JDSafeDesc(arg1), arg3, r);
    return r;
}

+ (void)enableEventPush:(BOOL)arg1 withPushPercent:(unsigned long long)arg2 {
    JDLog(@"+[JDBGuardModule enableEventPush:withPushPercent:] enable=%@ percent=%llu", JDYN(arg1), arg2);
    %orig(arg1, arg2);
}

%end


%hook JDBGuardHelper

+ (BOOL)application:(id)arg1 didFinishLaunchingWithOptions:(id)arg2 {
    JDLog(@"==== UPLOAD JDBGuardHelper application:didFinishLaunchingWithOptions: 被调用 ====");
    BOOL r = %orig(arg1, arg2);
    return r;
}

+ (void)setupWithApplication:(id)arg1 options:(id)arg2 {
    JDLog(@"+[JDBGuardHelper setupWithApplication:options:] 被调用");
    %orig(arg1, arg2);
}

%end


%hook JDBFingerPrintModule

+ (id)localCUID {
    id r = %orig();
    JDDumpRet(@"+[JDBFingerPrintModule localCUID]", r);
    return r;
}

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDBFingerPrintModule sharedInstance]", r);
    return r;
}

- (void)fetchCUIDOnComplete:(id)arg1 {
    JDLog(@"-[JDBFingerPrintModule fetchCUIDOnComplete:] 被调用");
    %orig(arg1);
}

%end


%hook JDBLBSCheckFakeUtil

+ (id)util {
    id r = %orig();
    JDDumpRet(@"+[JDBLBSCheckFakeUtil util]", r);
    return r;
}

+ (BOOL)isJailedDevice {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDBLBSCheckFakeUtil isJailedDevice]", JDYN(r));
    return r;
}

- (BOOL)shouldReportLocationLogWithCurrLat:(double)arg1 currLng:(double)arg2 {
    BOOL r = %orig(arg1, arg2);
    JDLog(@"-[JDBLBSCheckFakeUtil shouldReportLocationLogWithCurrLat:currLng:] lat=%f lng=%f ret=%@", arg1, arg2, JDYN(r));
    return r;
}

- (id)checkResultM3M2 {
    id r = %orig();
    JDDumpRet(@"-[JDBLBSCheckFakeUtil checkResultM3M2]（是否软件模拟/硬件外设模拟/越狱）", r);
    return r;
}

%end


%hook JDBJRDecisionModule

+ (id)routerHandle_JDBJRDecisionModule_getRiskData:(id)arg1 callback:(id)arg2 {
    JDDumpUpload(@"JDBJRDecisionModule getRiskData 请求参数", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"JDBJRDecisionModule getRiskData 同步返回值", r);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_getCacheToken:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDBJRDecisionModule getCacheToken 请求参数", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"JDBJRDecisionModule getCacheToken 同步返回值", r);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_fetchCUIDWithPin:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDBJRDecisionModule fetchCUIDWithPin 参数", arg1);
    id r = %orig(arg1, arg2);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_fetchCUID:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDBJRDecisionModule fetchCUID 参数", arg1);
    id r = %orig(arg1, arg2);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_getToken:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDBJRDecisionModule getToken 参数", arg1);
    id r = %orig(arg1, arg2);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_targetServer:(id)arg1 callback:(id)arg2 {
    JDDumpRet(@"JDBJRDecisionModule targetServer 参数（可能直接暴露服务器域名）", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"JDBJRDecisionModule targetServer 返回值", r);
    return r;
}

+ (id)routerHandle_JDBJRDecisionModule_SDKVersion:(id)arg1 callback:(id)arg2 {
    id r = %orig(arg1, arg2);
    JDDumpRet(@"JDBJRDecisionModule SDKVersion", r);
    return r;
}

%end


%hook JDBRiskColorNetWork

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDBRiskColorNetWork sharedInstance]", r);
    return r;
}



- (void)reportLogWithParameters:(id)arg1 source:(id)arg2 {
    JDLog(@"==== UPLOAD JDBRiskColorNetWork reportLogWithParameters source=%@ ====",
          JDSafeDesc(arg2));

    JDDumpUpload(@"JDBRiskColorNetWork reportLog parameters", arg1);

    %orig(arg1, arg2);
}

%end


%hook JDBHMacSHA256Sign

+ (id)lbshmacSHA256WithSecret:(id)arg1 content:(id)arg2 {
    JDDumpRet(@"+[JDBHMacSHA256Sign lbshmacSHA256WithSecret:] SECRET", arg1);
    JDDumpRet(@"+[JDBHMacSHA256Sign lbshmacSHA256WithSecret:content:] 待签名内容", arg2);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JDBHMacSHA256Sign lbshmacSHA256WithSecret:] 签名结果", r);
    return r;
}

%end


// ============================================================
// 【第3部分】全局熔断开关 + 本地错误缓存
// ============================================================

%hook JDGuardEventMgr

+ (id)sharedManager {
    id r = %orig();
    JDDumpRet(@"+[JDGuardEventMgr sharedManager]", r);
    return r;
}

- (BOOL)tryRefeashOrCheckGlobalTerminationState {
    BOOL r = %orig();
    JDDumpPrim(@"-[JDGuardEventMgr tryRefeashOrCheckGlobalTerminationState]（全局终止总开关状态）", JDYN(r));
    return r;
}

- (void)saveBadInfoWithErrCode:(long long)arg1 errMsg:(id)arg2 otherInfo:(id)arg3 {
    JDLog(@"==== UPLOAD JDGuardEventMgr saveBadInfoWithErrCode: errCode=%lld errMsg=%@ ====", arg1, JDSafeDesc(arg2));
    JDDumpUpload(@"JDGuardEventMgr saveBadInfo otherInfo", arg3);
    %orig(arg1, arg2, arg3);
}

- (BOOL)_needReportLocalBadInfos {
    BOOL r = %orig();
    JDDumpPrim(@"-[JDGuardEventMgr _needReportLocalBadInfos]", JDYN(r));
    return r;
}

- (void)_tryReportLocalBadInfos {
    JDLog(@"==== UPLOAD JDGuardEventMgr _tryReportLocalBadInfos 本地缓存的错误信息批量上报 ====");
    %orig();
}

- (id)_loadAndResetBadInfo {
    id r = %orig();
    JDDumpRet(@"-[JDGuardEventMgr _loadAndResetBadInfo]（取出并清空本地错误缓存）", r);
    return r;
}

- (void)updateTerminationEventDefinition:(id)arg1 {
    JDDumpUpload(@"JDGuardEventMgr updateTerminationEventDefinition（被叫停的事件清单）", arg1);
    %orig(arg1);
}

- (void)updateInvokeEventDefinition:(id)arg1 {
    JDDumpUpload(@"JDGuardEventMgr updateInvokeEventDefinition（允许执行的事件清单）", arg1);
    %orig(arg1);
}

%end


// ============================================================
// 【第4部分】行为生物特征与设备缓存
// ============================================================

%hook JDJR_Biological_CacheManager

+ (id)stringByApplyingCaesarCipher:(id)arg1 WithOffset:(long long)arg2 {
    id r = %orig(arg1, arg2);
    JDLog(@"+[JDJR_Biological_CacheManager stringByApplyingCaesarCipher:WithOffset:] input=%@ offset=%lld output=%@", JDSafeDesc(arg1), arg2, JDSafeDesc(r));
    return r;
}

+ (id)loginPin {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Biological_CacheManager loginPin]", r);
    return r;
}

+ (id)creatLocalToken {
    id r = %orig();
    JDDumpRet(@"+[JDJR_Biological_CacheManager creatLocalToken]", r);
    return r;
}

- (void)handleUIApplicationDidTakeScreenshotNotification:(id)arg1 {
    JDLog(@"-[JDJR_Biological_CacheManager handleUIApplicationDidTakeScreenshotNotification:] 用户截屏了，SDK收到了通知");
    %orig(arg1);
}

- (void)stopScreen {
    JDLog(@"-[JDJR_Biological_CacheManager stopScreen]");
    %orig();
}

+ (BOOL)saveData:(id)arg1 service:(id)arg2 account:(id)arg3 attrAccess:(id)arg4 {
    JDLog(@"+[JDJR_Biological_CacheManager saveData:service:account:] service=%@ account=%@", JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JDJR_Biological_CacheManager saveData（写入Keychain的数据）", arg1);
    BOOL r = %orig(arg1, arg2, arg3, arg4);
    return r;
}

+ (id)readDataWithService:(id)arg1 account:(id)arg2 attrAccess:(id)arg3 {
    id r = %orig(arg1, arg2, arg3);
    JDLog(@"+[JDJR_Biological_CacheManager readDataWithService:account:] service=%@ account=%@", JDSafeDesc(arg1), JDSafeDesc(arg2));
    JDDumpRet(@"JDJR_Biological_CacheManager readData（读出的Keychain数据）", r);
    return r;
}

+ (id)topViewController {
    id r = %orig();
    JDLog(@"+[JDJR_Biological_CacheManager topViewController] class=%@", r ? NSStringFromClass([r class]) : @"(nil)");
    return r;
}

+ (id)getVCSubViews:(id)arg1 {
    id r = %orig(arg1);
    JDLog(@"+[JDJR_Biological_CacheManager getVCSubViews:] 输入VC=%@ 数量=%@",
          arg1 ? NSStringFromClass([arg1 class]) : @"(nil)",
          [r respondsToSelector:@selector(count)] ? @([r count]).stringValue : @"?");
    return r;
}

%end


%hook JDJR_BehaviorEnv

+ (id)unique_baseUrl {
    id r = %orig();
    JDDumpRet(@"+[JDJR_BehaviorEnv unique_baseUrl]", r);
    return r;
}

+ (void)configUnique_baseUrl:(id)arg1 options:(id)arg2 {
    JDLog(@"+[JDJR_BehaviorEnv configUnique_baseUrl:options:] url=%@", JDSafeDesc(arg1));
    JDDumpRet(@"JDJR_BehaviorEnv configUnique_baseUrl options", arg2);
    %orig(arg1, arg2);
}

%end


%hook JDJR_Biological_BuryingPoint

+ (void)buryingPointWithBizId:(id)arg1 options:(id)arg2 error:(id)arg3 model:(id)arg4 {
    JDLog(@"==== UPLOAD Biological_BuryingPoint bizId=%@", JDSafeDesc(arg1));
    JDDumpUpload(@"Biological_BuryingPoint options", arg2);
    %orig(arg1, arg2, arg3, arg4);
}

+ (void)buryingPointWithBizId:(id)arg1 eventId:(id)arg2 options:(id)arg3 error:(id)arg4 model:(id)arg5 {
    JDLog(@"==== UPLOAD Biological_BuryingPoint bizId=%@ eventId=%@", JDSafeDesc(arg1), JDSafeDesc(arg2));
    JDDumpUpload(@"Biological_BuryingPoint options", arg3);
    %orig(arg1, arg2, arg3, arg4, arg5);
}

%end


%hook JRRisk_DeviceUtil

+ (id)getHardware {
    id r = %orig();
    JDDumpRet(@"+[JRRisk_DeviceUtil getHardware]", r);
    return r;
}

+ (BOOL)saveData:(id)arg1 service:(id)arg2 account:(id)arg3 attrAccess:(id)arg4 {
    JDLog(@"+[JRRisk_DeviceUtil saveData:service:account:] service=%@ account=%@", JDSafeDesc(arg2), JDSafeDesc(arg3));
    JDDumpUpload(@"JRRisk_DeviceUtil saveData（写入Keychain的数据）", arg1);
    BOOL r = %orig(arg1, arg2, arg3, arg4);
    return r;
}

+ (id)readDataWithService:(id)arg1 account:(id)arg2 attrAccess:(id)arg3 {
    id r = %orig(arg1, arg2, arg3);
    JDLog(@"+[JRRisk_DeviceUtil readDataWithService:account:] service=%@ account=%@", JDSafeDesc(arg1), JDSafeDesc(arg2));
    JDDumpRet(@"JRRisk_DeviceUtil readData（读出的Keychain数据）", r);
    return r;
}

+ (void)JRRisk_BackUp_HardwareWithUserDefultKey:(id)arg1 key:(id)arg2 acount:(id)arg3 service:(id)arg4 service_noBack:(id)arg5 {
    JDLog(@"+[JRRisk_DeviceUtil JRRisk_BackUp_HardwareWithUserDefultKey:...] userDefaultKey=%@ key=%@", JDSafeDesc(arg1), JDSafeDesc(arg2));
    %orig(arg1, arg2, arg3, arg4, arg5);
}

+ (BOOL)isNeedLoadOrigin {
    BOOL r = %orig();
    JDDumpPrim(@"+[JRRisk_DeviceUtil isNeedLoadOrigin]", JDYN(r));
    return r;
}

%end


// ============================================================
// 【第6部分】完全没被提及的辅助模块
// ============================================================

%hook JRRisk_AES

+ (id)AES128operation:(unsigned int)arg1 Data:(id)arg2 Key:(id)arg3 iv:(id)arg4 {
    JDDumpRet(@"+[JRRisk_AES AES128operation:Data:] 输入数据", arg2);
    JDDumpRet(@"+[JRRisk_AES AES128operation:Key:]", arg3);
    id r = %orig(arg1, arg2, arg3, arg4);
    JDDumpRet(@"+[JRRisk_AES AES128operation:] 结果", r);
    return r;
}

+ (id)AES128DecryptStrData:(id)arg1 Key:(id)arg2 iv:(id)arg3 {
    JDDumpRet(@"+[JRRisk_AES AES128DecryptStrData:] 密文输入", arg1);
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"+[JRRisk_AES AES128DecryptStrData:] 解密后明文", r);
    return r;
}

+ (id)AES128EncryptJsonData:(id)arg1 Key:(id)arg2 iv:(id)arg3 {
    JDDumpRet(@"+[JRRisk_AES AES128EncryptJsonData:] 明文JSON输入", arg1);
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"+[JRRisk_AES AES128EncryptJsonData:] 加密后结果", r);
    return r;
}

%end

%hook JRRisk_RSA

+ (id)encryptData:(id)arg1 publicKey:(id)arg2 {
    JDDumpRet(@"+[JRRisk_RSA encryptData:publicKey:] 明文输入", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JRRisk_RSA encryptData:publicKey:] 密文结果", r);
    return r;
}

+ (id)decryptData:(id)arg1 privateKey:(id)arg2 {
    JDDumpRet(@"+[JRRisk_RSA decryptData:privateKey:] 密文输入", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JRRisk_RSA decryptData:privateKey:] 解密后明文", r);
    return r;
}

%end

%hook JRRisk_Sha_XX

+ (id)sha256:(id)arg1 {
    JDDumpRet(@"+[JRRisk_Sha_XX sha256:] 输入", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[JRRisk_Sha_XX sha256:] 结果", r);
    return r;
}

+ (id)sha1:(id)arg1 {
    JDDumpRet(@"+[JRRisk_Sha_XX sha1:] 输入", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"+[JRRisk_Sha_XX sha1:] 结果", r);
    return r;
}

%end


%hook JDGuardRollBackMode

- (void)setEver:(long long)arg1 {
    JDDumpPrim(@"-[JDGuardRollBackMode setEver:]", @(arg1).stringValue);
    %orig(arg1);
}

- (void)setPver:(long long)arg1 {
    JDDumpPrim(@"-[JDGuardRollBackMode setPver:]", @(arg1).stringValue);
    %orig(arg1);
}

%end


%hook JDGuardTask2
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDGuardTask2 sharedInstance]", r);
    return r;
}
- (void)startWorkWithSence:(id)arg1 {
    JDLog(@"-[JDGuardTask2 startWorkWithSence:] sence=%@", JDSafeDesc(arg1));
    %orig(arg1);
}
%end

%hook JDGuardTask5
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDGuardTask5 sharedInstance]", r);
    return r;
}
- (void)startWork {
    JDLog(@"-[JDGuardTask5 startWork] 被调用");
    %orig();
}
%end

%hook JDGuardTask6
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDGuardTask6 sharedInstance]", r);
    return r;
}
- (void)startWorkWithCanRetry:(BOOL)arg1 {
    JDLog(@"-[JDGuardTask6 startWorkWithCanRetry:] canRetry=%@", JDYN(arg1));
    %orig(arg1);
}
%end


%hook JDGuardUpgradeMgr

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDGuardUpgradeMgr sharedInstance]", r);
    return r;
}

- (void)didUpdateUpgradeInfoWithPver:(long long)arg1 ever:(long long)arg2 {
    JDLog(@"-[JDGuardUpgradeMgr didUpdateUpgradeInfoWithPver:ever:] pver=%lld ever=%lld", arg1, arg2);
    %orig(arg1, arg2);
}

%end


%hook QNHijackingDetectWrapper

- (id)query:(id)arg1 networkInfo:(id)arg2 error:(id *)arg3 {
    JDLog(@"-[QNHijackingDetectWrapper query:networkInfo:] query=%@", JDSafeDesc(arg1));
    JDDumpRet(@"QNHijackingDetectWrapper networkInfo", arg2);
    id r = %orig(arg1, arg2, arg3);
    JDDumpRet(@"QNHijackingDetectWrapper query结果", r);
    return r;
}

%end


%hook JDBJMATouchManager

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDBJMATouchManager sharedInstance]", r);
    return r;
}

- (void)touchHandle:(long long)arg1 pointInfo:(id)arg2 {
    JDDumpUpload(@"JDBJMATouchManager touchHandle 触摸坐标信息", arg2);
    %orig(arg1, arg2);
}

- (BOOL)reportUserBehaviors:(id)arg1 {
    JDLog(@"==== UPLOAD JDBJMATouchManager reportUserBehaviors ====");
    JDDumpUpload(@"JDBJMATouchManager 用户行为数据", arg1);
    BOOL r = %orig(arg1);
    return r;
}

- (void)pageTrackStart:(id)arg1 view:(id)arg2 params:(id)arg3 {
    JDLog(@"-[JDBJMATouchManager pageTrackStart:view:params:] page=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}

- (void)pageTrackEnd:(id)arg1 view:(id)arg2 params:(id)arg3 {
    JDLog(@"-[JDBJMATouchManager pageTrackEnd:view:params:] page=%@", JDSafeDesc(arg1));
    %orig(arg1, arg2, arg3);
}

- (void)pageTrackReport:(id)arg1 params:(id)arg2 {
    JDLog(@"==== UPLOAD JDBJMATouchManager pageTrackReport page=%@ ====", JDSafeDesc(arg1));
    JDDumpUpload(@"JDBJMATouchManager pageTrackReport params", arg2);
    %orig(arg1, arg2);
}

%end


%hook JDBSafeIPManager

+ (id)sharedJDBSafeIPManager {
    id r = %orig();
    JDDumpRet(@"+[JDBSafeIPManager sharedJDBSafeIPManager]", r);
    return r;
}

- (void)StartReturnSafeIP {
    JDLog(@"-[JDBSafeIPManager StartReturnSafeIP] 被调用");
    %orig();
}

- (id)getSafeIPbyHost:(id)arg1 {
    id r = %orig(arg1);
    JDLog(@"-[JDBSafeIPManager getSafeIPbyHost:] host=%@ 结果=%@", JDSafeDesc(arg1), JDSafeDesc(r));
    return r;
}

- (void)setReturnSafeIPByError:(id)arg1 {
    JDLog(@"-[JDBSafeIPManager setReturnSafeIPByError:] error=%@", JDSafeDesc(arg1));
    %orig(arg1);
}

%end


%hook JDBRandomOpenUDIDManager

+ (id)sharedManager {
    id r = %orig();
    JDDumpRet(@"+[JDBRandomOpenUDIDManager sharedManager]", r);
    return r;
}

- (void)__internalInit {
    JDLog(@"-[JDBRandomOpenUDIDManager __internalInit] 被调用");
    %orig();
}

%end


%hook JDBLBSReportManager

+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDBLBSReportManager sharedInstance]", r);
    return r;
}

- (id)userPin {
    id r = %orig();
    JDDumpRet(@"-[JDBLBSReportManager userPin]", r);
    return r;
}

- (void)lbsLocationNewMonitoringReportWithAppId:(id)arg1 callkey:(long long)arg2 requestParams:(id)arg3 responseCode:(long long)arg4 responseMsg:(id)arg5 response:(id)arg6 timeSpan:(double)arg7 fakeInfo:(BOOL)arg8 ltp:(id)arg9 rtm:(id)arg10 updateGPSList:(id)arg11 isContinuous:(id)arg12 {
    JDLog(@"==== UPLOAD JDBLBSReportManager lbsLocationNewMonitoringReport fakeInfo=%@ responseCode=%lld ====", JDYN(arg8), arg4);
    JDDumpUpload(@"JDBLBSReportManager requestParams", arg3);
    %orig(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12);
}

- (void)reportLBSException:(id)arg1 WithMap:(id)arg2 {
    JDLog(@"==== UPLOAD JDBLBSReportManager reportLBSException:WithMap: exception=%@ ====", JDSafeDesc(arg1));
    JDDumpUpload(@"JDBLBSReportManager exception map", arg2);
    %orig(arg1, arg2);
}

- (void)draReporWithBizID:(id)arg1 EventName:(id)arg2 WithMap:(id)arg3 {
    JDLog(@"==== UPLOAD JDBLBSReportManager draReporWithBizID: bizId=%@ event=%@ ====", JDSafeDesc(arg1), JDSafeDesc(arg2));
    JDDumpUpload(@"JDBLBSReportManager draReport map", arg3);
    %orig(arg1, arg2, arg3);
}

%end
#pragma mark - 遗漏补充 1: 高强度混淆安全类与 Mach-O 内存检测

%hook JDMachOInfo
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[JDMachOInfo sharedInstance]", r);
    return r;
}
- (BOOL)checkDylibInjection {
    BOOL r = %orig();
    JDDumpPrim(@"-[JDMachOInfo checkDylibInjection]", JDYN(r));
    return r;
}
%end

%hook JDGuardXXTEA
+ (id)encryptData:(id)arg1 key:(id)arg2 {
    JDDumpRet(@"+[JDGuardXXTEA encryptData:] 明文", arg1);
    id r = %orig(arg1, arg2);
    JDDumpRet(@"+[JDGuardXXTEA encryptData:] 密文", r);
    return r;
}
%end

%hook JDGuardIRMgr
+ (id)sharedManager {
    id r = %orig();
    JDDumpRet(@"+[JDGuardIRMgr sharedManager]", r);
    return r;
}
- (void)startIRCheck {
    JDLog(@"-[JDGuardIRMgr startIRCheck] 被调用");
    %orig();
}
%end

// 混淆类：通常在 init 时会进行环境扫描，记录一下调用时机
%hook JDGS_pellucidly
- (id)init {
    id r = %orig();
    JDLog(@"==== UPLOAD 混淆安全类 JDGS_pellucidly 初始化 ====");
    return r;
}
%end

%hook JDGAI_bedscrew
- (id)init {
    id r = %orig();
    JDLog(@"==== UPLOAD 混淆安全类 JDGAI_bedscrew 初始化 ====");
    return r;
}
%end

%hook JDGDU_micrography
- (id)init {
    id r = %orig();
    JDLog(@"==== UPLOAD 混淆安全类 JDGDU_micrography 初始化 ====");
    return r;
}
%end

%hook JDGB_microdactylism
- (id)init {
    id r = %orig();
    JDLog(@"==== UPLOAD 混淆安全类 JDGB_microdactylism 初始化 ====");
    return r;
}
%end
#pragma mark - 遗漏补充 2: 阿里与腾讯系设备指纹 / 传感器探针

// 阿里安全设备指纹与 UTDID
%hook AliSecXDeviceInfoMXXTIY
+ (id)getDeviceInfo {
    id r = %orig();
    JDDumpRet(@"+[AliSecXDeviceInfoMXXTIY getDeviceInfo]", r);
    return r;
}
%end

%hook UTDIDBaseUtils
+ (id)getUtdid {
    id r = %orig();
    JDDumpRet(@"+[UTDIDBaseUtils getUtdid]", r);
    return r;
}
%end

// 蚂蚁金服 UMID Token 收集器
%hook ASSUmidTokenCollector
- (void)startCollectUmidToken {
    JDLog(@"-[ASSUmidTokenCollector startCollectUmidToken] 启动收集");
    %orig();
}
%end

// 腾讯 Beacon (灯塔) QIMEI 收集
%hook TMSBeaconWupQimeiPackage
- (id)getQimei {
    id r = %orig();
    JDDumpRet(@"-[TMSBeaconWupQimeiPackage getQimei]", r);
    return r;
}
%end

// 腾讯惯性导航引擎 (Dead Reckoning) - 极具威胁，用于判断真实骑行状态
%hook TencentDRSensorManager
+ (id)sharedInstance {
    id r = %orig();
    JDDumpRet(@"+[TencentDRSensorManager sharedInstance]", r);
    return r;
}
- (void)startSensorUpdates {
    JDLog(@"-[TencentDRSensorManager startSensorUpdates] 启动传感器");
    %orig();
}
%end

%hook TencentDRMotionActivityManager
- (void)startActivityUpdates {
    JDLog(@"-[TencentDRMotionActivityManager startActivityUpdates] 启动运动状态监控");
    %orig();
}
%end

%hook TencentDrLocation
- (void)uploadDrLocation:(id)arg1 {
    JDLog(@"==== UPLOAD TencentDrLocation ====");
    JDDumpUpload(@"TencentDrLocation data", arg1);
    %orig(arg1);
}
%end
#pragma mark - 遗漏补充 3: 行为验证与人脸核身

// 行为验证码滑块 / 拼图
%hook JDJR_SliderVerify
- (void)showVerifyViewWithConfig:(id)arg1 {
    JDLog(@"==== 触发风控行为验证弹窗 JDJR_SliderVerify ====");
    JDDumpRet(@"JDJR_SliderVerify Config", arg1);
    %orig(arg1);
}
%end

%hook JDJR_YuYiVerifyView
- (void)show {
    JDLog(@"==== 触发风控语义验证弹窗 JDJR_YuYiVerifyView ====");
    %orig();
}
%end

%hook JDJMAHumanComputerHelper
+ (BOOL)isHumanOperating {
    BOOL r = %orig();
    JDDumpPrim(@"+[JDJMAHumanComputerHelper isHumanOperating]", JDYN(r));
    return r;
}
%end

// 人脸识别检测
%hook jdcnFaceIdentifyManage
- (void)startFaceDetectWithConfig:(id)arg1 {
    JDLog(@"==== 触发人脸识别 jdcnFaceIdentifyManage ====");
    JDDumpRet(@"Face Config", arg1);
    %orig(arg1);
}
%end

%hook jdcnFaceNoFeelActoionView
- (void)startNoFeelCheck {
    JDLog(@"==== 触发后台静默无感活体抓拍 jdcnFaceNoFeelActoionView ====");
    %orig();
}
%end
#pragma mark - 遗漏补充 4: 抓包诊断、网关隔离与跨区风控

// 网络代理环境主动侦测（测速发包探测）
%hook PhonePing
- (void)startPing:(id)arg1 {
    JDLog(@"-[PhonePing startPing:] host=%@", JDSafeDesc(arg1));
    %orig(arg1);
}
%end

%hook PNTcpPing
- (void)start {
    JDLog(@"-[PNTcpPing start] 被调用");
    %orig();
}
%end

%hook PNUdpTracerouteDetail
- (void)startTraceroute {
    JDLog(@"-[PNUdpTracerouteDetail startTraceroute] 被调用 (路由追踪侦测中间人)");
    %orig();
}
%end

// 达达骑士端特定的业务安全插件
%hook _TtC9DadaStaff28NDDColorSignAndEncryptPlugin
- (id)signWithParameters:(id)arg1 {
    JDDumpRet(@"-[NDDColorSignAndEncryptPlugin signWithParameters:] 待签参数", arg1);
    id r = %orig(arg1);
    JDDumpRet(@"-[NDDColorSignAndEncryptPlugin signWithParameters:] 签名结果", r);
    return r;
}
%end

%hook _TtC9DadaStaff34STFStaffBeyondGridDetectionManager
- (void)detectGridLimitWithLocation:(id)arg1 {
    JDLog(@"==== UPLOAD 触发网格/超区围栏检测 STFStaffBeyondGridDetectionManager ====");
    JDDumpUpload(@"Grid Location", arg1);
    %orig(arg1);
}
%end
#pragma mark - 遗漏补充 5: APM 性能监控与崩溃日志上报

%hook JDAPMReport
+ (void)reportWithData:(id)arg1 type:(id)arg2 {
    JDLog(@"==== UPLOAD JDAPMReport type=%@ ====", JDSafeDesc(arg2));
    JDDumpUpload(@"JDAPMReport data", arg1);
    %orig(arg1, arg2);
}
%end

%hook JDBacktraceLogger
+ (id)jd_backtraceOfAllThread {
    JDLog(@"==== UPLOAD JDBacktraceLogger (App卡顿或异常, 正在收集全线程调用栈) ====");
    id r = %orig();
    return r;
}
%end

%hook KSCrashDeadlockMonitor
- (void)handleDeadlock {
    JDLog(@"==== 触发死锁监控 KSCrashDeadlockMonitor ====");
    %orig();
}
%end

%hook JDCrashANRTracker
- (void)reportANR {
    JDLog(@"==== 触发ANR无响应监控 JDCrashANRTracker ====");
    %orig();
}
%end

// 达达专门的日志聚合上报系统
%hook _TtC22DDMonitorUploadManager22DDMonitorUploadManager
- (void)uploadMonitorData:(id)arg1 {
    JDLog(@"==== UPLOAD 达达性能与异常聚合上传 DDMonitorUploadManager ====");
    JDDumpUpload(@"Upload Data", arg1);
    %orig(arg1);
}
%end
// 静态链接时算出来的偏移量(相对__TEXT段基址)，来自对DadaStaff二进制的反汇编分析：
// 0x1f4560 = 那段处理"i_userId_config"等一批配置名的Swift函数入口
#define TARGET_FUNC_OFFSET 0x1f4560

// 原函数指针，%orig的手动版本
static void (*orig_userIdConfigFunc)(void *x0, void *x1, void *x2, void *x3);

// 替换后的函数：先把参数打出来，再原样传给真正的函数继续执行
static void hooked_userIdConfigFunc(void *x0, void *x1, void *x2, void *x3) {
    JDLog(@"==== [疑似] i_userId_config 处理函数被调用 ====");
    JDLog(@"  x0(可能是self/上下文) = %p", x0);
    JDLog(@"  x1(可能是参数1)       = %p", x1);
    JDLog(@"  x2(可能是参数2)       = %p", x2);
    JDLog(@"  x3(可能是参数3)       = %p", x3);

    // 如果这几个寄存器碰巧是Objective-C对象指针(比如桥接过来的NSString/NSArray),
    // 尝试安全地打印出它的内容，打印失败也不会崩溃(JDSafeDesc内部有@try保护)
    JDLog(@"  x0 尝试当作OC对象打印: %@", JDSafeDesc((__bridge id)x0));
    JDLog(@"  x1 尝试当作OC对象打印: %@", JDSafeDesc((__bridge id)x1));
    JDLog(@"  x2 尝试当作OC对象打印: %@", JDSafeDesc((__bridge id)x2));
    JDLog(@"  x3 尝试当作OC对象打印: %@", JDSafeDesc((__bridge id)x3));

    // 原样调用真正的函数，让它正常往下执行（该判断该处理都不受影响）
    orig_userIdConfigFunc(x0, x1, x2, x3);
}




#pragma mark - ctor

%ctor {
    NSString *path = JDLogFilePath();
    JDLog(@"===== ctor ===== logFile=%@ home=%@", path, NSHomeDirectory());
    JDLog(@"filter prefix=%@", HOOK_PREFIX);

    // 新加的部分：i_userId_config 处理函数的原始地址hook
    const struct mach_header *header = _dyld_get_image_header(0);
    uintptr_t base = (uintptr_t)header;
    void *targetAddr = (void *)(base + TARGET_FUNC_OFFSET);
    JDLog(@"准备hook i_userId_config处理函数, 运行时地址 = %p (基址=%p + 偏移0x%lx)",
          targetAddr, (void *)base, (unsigned long)TARGET_FUNC_OFFSET);
    MSHookFunction(targetAddr, (void *)hooked_userIdConfigFunc, (void **)&orig_userIdConfigFunc);
}
