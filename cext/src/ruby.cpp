/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2008-2010 Wayne Meissner
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/

#include "Handle.h"
#include "jruby.h"
#include "ruby.h"
#include "JLocalEnv.h"
#include "JString.h"

extern "C" {

VALUE rb_mKernel;
VALUE rb_mComparable;
VALUE rb_mEnumerable;
VALUE rb_mErrno;
VALUE rb_mFileTest;
VALUE rb_mGC;
VALUE rb_mMath;
VALUE rb_mProcess;

VALUE rb_cObject;
VALUE rb_cArray;
VALUE rb_cBignum;
VALUE rb_cBinding;
VALUE rb_cClass;
VALUE rb_cDir;
VALUE rb_cData;
VALUE rb_cFalseClass;
VALUE rb_cFile;
VALUE rb_cFixnum;
VALUE rb_cFloat;
VALUE rb_cHash;
VALUE rb_cInteger;
VALUE rb_cIO;
VALUE rb_cMatch;
VALUE rb_cMethod;
VALUE rb_cModule;
VALUE rb_cNilClass;
VALUE rb_cNumeric;
VALUE rb_cProc;
VALUE rb_cRange;
VALUE rb_cRegexp;
VALUE rb_cString;
VALUE rb_cStruct;
VALUE rb_cSymbol;
VALUE rb_cThread;
VALUE rb_cTime;
VALUE rb_cTrueClass;

VALUE rb_eException;
VALUE rb_eStandardError;
VALUE rb_eSystemExit;
VALUE rb_eInterrupt;
VALUE rb_eSignal;
VALUE rb_eFatal;
VALUE rb_eArgError;
VALUE rb_eEOFError;
VALUE rb_eIndexError;
VALUE rb_eStopIteration;
VALUE rb_eRangeError;
VALUE rb_eIOError;
VALUE rb_eRuntimeError;
VALUE rb_eSecurityError;
VALUE rb_eSystemCallError;
VALUE rb_eThreadError;
VALUE rb_eTypeError;
VALUE rb_eZeroDivError;
VALUE rb_eNotImpError;
VALUE rb_eNoMemError;
VALUE rb_eNoMethodError;
VALUE rb_eFloatDomainError;
VALUE rb_eLocalJumpError;
VALUE rb_eSysStackError;
VALUE rb_eRegexpError;


VALUE rb_eScriptError;
VALUE rb_eNameError;
VALUE rb_eSyntaxError;
VALUE rb_eLoadError;

}
static VALUE getConstClass(JNIEnv* env, const char* name);
static VALUE getConstModule(JNIEnv* env, const char* name);

using namespace jruby;

jstring
getGlobalVariableName(JNIEnv* env, const char* name)
{
    char var_name[strlen(name) + 1];
    (name[0] != '$') ? strcpy(var_name, "$")[0] : var_name[0] = '\0';
    strcat(var_name, name);

    return env->NewStringUTF(var_name);
}

/**
 * Define a global constant. Uses the corresponding Java method on
 * the Ruby class.
 * @param c string with the constant name
 * @param Ruby object to define the variable on
 */
extern "C" void
rb_define_global_const(const char* name, VALUE obj)
{
    JLocalEnv env;

    jmethodID mid = getMethodID(env, Ruby_class, "defineGlobalConstant",
            "(Ljava/lang/String;Lorg/jruby/runtime/builtin/IRubyObject;)V");
    env->CallObjectMethod(getRuntime(), mid, env->NewStringUTF(name), valueToObject(env, obj));
}

extern "C" VALUE
rb_gv_get(const char* name)
{
    JLocalEnv env;

    jlong result = env->CallStaticLongMethod(JRuby_class, JRuby_gv_get_method, getRuntime(),
            getGlobalVariableName(env, name));
    checkExceptions(env);

    return (VALUE)result;
}

extern "C" VALUE
rb_gv_set(const char* name, VALUE value)
{
    JLocalEnv env;

    jlong result = env->CallStaticLongMethod(JRuby_class, JRuby_gv_set_method, getRuntime(),
            getGlobalVariableName(env, name), valueToObject(env, value));
    checkExceptions(env);

    return (VALUE)result;
}

extern "C" void
rb_define_readonly_variable(const char* name, VALUE* value)
{
    JLocalEnv env;
    jstring varName;
    if (name[0] == '$') {
        varName = env->NewStringUTF(name);
    } else {
        char _name[strlen(name) + 2];
        _name[0] = '$';
        _name[1] = '\0';
        strcat(_name, name);
        varName = env->NewStringUTF(_name);
    }
    env->CallVoidMethod(getRuntime(), Ruby_defineReadonlyVariable_method, varName, valueToObject(env, *value));
    checkExceptions(env);
}

extern "C" VALUE
rb_f_global_variables()
{
    return callMethod(rb_mKernel, "global_variables", 0);
}

extern "C" void
rb_set_kcode(const char *code)
{
    rb_gv_set("$KCODE", rb_str_new_cstr(code));
}

extern "C" VALUE
rb_eval_string(const char* string)
{
    JLocalEnv env;

    jmethodID mid = getMethodID(env, Ruby_class, "evalScriptlet",
            "(Ljava/lang/String;)Lorg/jruby/runtime/builtin/IRubyObject;");
    jobject result = env->CallObjectMethod(getRuntime(), mid, env->NewStringUTF(string));
    checkExceptions(env);
    return objectToValue(env, result);
}

extern "C" void
rb_sys_fail(const char* msg)
{
    JLocalEnv env;
    env->CallVoidMethod(JRuby_class, JRuby_sysFail, getRuntime(), env->NewStringUTF(msg));
}

extern "C" void
rb_throw(const char* symbol, VALUE result)
{
    VALUE params[2] = {ID2SYM(rb_intern(symbol)), result};
    callMethodA(rb_mKernel, "throw", 2, params);
}

#define M(x) rb_m##x = getConstModule(env, #x)
#define C(x) rb_c##x = getConstClass(env, #x)
#define E(x) rb_e##x = getConstClass(env, #x)

void
jruby::initRubyClasses(JNIEnv* env, jobject runtime)
{
    M(Kernel);
    M(Comparable);
    M(Enumerable);
    M(Errno);
    M(FileTest);
    M(Math);
    M(Process);

    C(Object);
    C(Array);
    C(Bignum);
    C(Binding);
    C(Class);
    C(Dir);
    C(Data);
    C(FalseClass);
    C(File);
    C(Fixnum);
    C(Float);
    C(Hash);
    C(Integer);
    C(IO);
    rb_cMatch = getConstClass(env, "MatchData");
    C(Method);
    C(Module);
    C(NilClass);
    C(Numeric);
    C(Proc);
    C(Range);
    C(Regexp);
    C(String);
    C(Struct);
    C(Symbol);
    C(Thread);
    C(Time);
    C(TrueClass);

    E(Exception);
    E(StandardError);
    E(SystemExit);
    E(Interrupt);
    rb_eSignal = getConstClass(env, "SignalException");
    E(Fatal);
    rb_eArgError = getConstClass(env, "ArgumentError");
    E(EOFError);
    E(IndexError);
    E(StopIteration);
    E(RangeError);
    E(IOError);
    E(RuntimeError);
    E(SecurityError);
    E(SystemCallError);
    E(ThreadError);
    E(TypeError);
    rb_eZeroDivError = getConstClass(env, "ZeroDivisionError");
    rb_eNotImpError = getConstClass(env, "NotImplementedError");
    rb_eNoMemError = getConstClass(env, "NoMemoryError");
    E(NoMethodError);
    E(FloatDomainError);
    E(LocalJumpError);
    rb_eSysStackError = getConstClass(env, "SystemStackError");
    E(RegexpError);


    E(ScriptError);
    E(NameError);
    E(SyntaxError);
    E(LoadError);
}

static VALUE
getConstClass(JNIEnv* env, const char* name)
{
    VALUE v = jruby::getClass(env, name);
    jruby::Handle::valueOf(v)->flags |= FL_CONST;
    return v;
}

static VALUE
getConstModule(JNIEnv* env, const char* name)
{
    VALUE v = jruby::getModule(env, name);
    jruby::Handle::valueOf(v)->flags |= FL_CONST;
    return v;
}