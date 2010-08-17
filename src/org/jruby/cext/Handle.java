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


package org.jruby.cext;

import org.jruby.Ruby;
import org.jruby.RubyFixnum;
import org.jruby.RubyIO;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.runtime.ClassIndex;
import org.jruby.runtime.builtin.IRubyObject;

public final class Handle {
    private static final long FIXNUM_MAX = Integer.getInteger("sun.arch.data.model") == 32
            ? (Long.MAX_VALUE >> 1) : ((long) Integer.MAX_VALUE >> 1);
    private static final long FIXNUM_MIN = Integer.getInteger("sun.arch.data.model") == 32
            ? (Long.MIN_VALUE >> 1) : ((long) Integer.MIN_VALUE >> 1);

    @SuppressWarnings("unused")
    private final Ruby runtime;
    private final long address;
    
    static Handle newHandle(Ruby runtime, Object rubyObject, long nativeHandle) {
        return new Handle(runtime, nativeHandle);
    }
    
    private Handle(Ruby runtime, long address) {
        this.runtime = runtime;
        this.address = address;
    }
    
    public final long getAddress() {
        return address;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Handle other = (Handle) obj;
        return this.address == other.address;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + (int) (this.address ^ (this.address >>> 32));
        return hash;
    }

    @Override
    public String toString() {
        return "Native ruby object " + Long.toString(address);
    }

    static Handle valueOf(IRubyObject obj) {
        Handle h = GC.lookup(obj);
        if (h != null) {
            return h;
        }

        Ruby runtime = obj.getRuntime();
        long nativeHandle;


        if (obj instanceof RubyObject) {
            int type = ((RubyObject) obj).getNativeTypeIndex();
            switch (type) {
                case ClassIndex.FIXNUM: {
                    final long val = ((RubyFixnum) obj).getLongValue();
                    nativeHandle = (val < FIXNUM_MAX && val >= FIXNUM_MIN)
                            ? ((val << 1) | 0x1)
                            : Native.getInstance(runtime).newFixnumHandle(obj, val);
                    }
                    break;

                case ClassIndex.FLOAT:
                    nativeHandle = Native.getInstance(runtime).newFloatHandle(obj, ((RubyNumeric) obj).getDoubleValue());
                    break;

                case ClassIndex.SYMBOL:
                    nativeHandle = ((long) ((RubySymbol) obj).getId() << 8) | 0xeL;
                    break;

                case ClassIndex.FILE: // RubyIO uses FILE as type index, matching MRI's T_FILE
                    nativeHandle = Native.getInstance(runtime).newIOHandle(obj,
                            ((RubyIO) obj).getOpenFile().getMainStream().getDescriptor().getFileDescriptor(),
                            ((RubyIO) obj).getOpenFile().getModeAsString(runtime));
                    break;

                default:
                    nativeHandle = Native.getInstance(runtime).newHandle(obj, type);
                    break;
            }
        } else {
            nativeHandle = Native.getInstance(runtime).newHandle(obj, ClassIndex.OBJECT);
        }

        Handle handle = newHandle(runtime, obj, nativeHandle);

        GC.register(obj, handle);

        return handle;
    }

    static long nativeHandle(IRubyObject obj) {
        if (obj.getClass() == RubyFixnum.class) {
            final long val = ((RubyFixnum) obj).getLongValue();
            if (val < FIXNUM_MAX && val >= FIXNUM_MIN) {
                return ((val << 1) | 0x1);
            }
        
        } else if (obj.getClass() == RubySymbol.class) {
            return ((long) ((RubySymbol) obj).getId() << 8) | 0xeL;
        }

        return Handle.valueOf(obj).getAddress();
    }
}