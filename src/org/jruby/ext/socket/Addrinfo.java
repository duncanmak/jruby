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
 * Copyright (C) 2011 Duncan Mak <duncan@earthaid.net>
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
package org.jruby.ext.socket;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

@JRubyClass(name="Addrinfo")
public class Addrinfo extends RubyObject {

    private static final ObjectAllocator ADDRINFO_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new Addrinfo(runtime, klass);
        }
    };

    static void createAddrinfo(Ruby runtime) {
        RubyClass result = runtime.defineClass("Addrinfo", runtime.getObject(), ADDRINFO_ALLOCATOR);
        result.setReifiedClass(Addrinfo.class);
        result.defineAnnotatedMethods(Addrinfo.class);
    }
    
    public Addrinfo(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
    }


    public Addrinfo(Ruby runtime, InetAddress address) {
        super(runtime, runtime.getClass("Addrinfo"));
        this.address = address;
    }

    private InetAddress address;

    @JRubyMethod(meta = true)
    public static IRubyObject ip(IRubyObject self, IRubyObject arg) {
        Ruby runtime = self.getRuntime();
        try {
            String host = arg.convertToString().toString();
            return new Addrinfo(runtime, InetAddress.getByName(host));
        } catch (UnknownHostException e) {
            throw new RaiseException(
                runtime, runtime.getClass("SocketError"), "getaddrinfo: Name or service not known", true);
        }
    }

    @JRubyMethod(meta = true)
    public static IRubyObject tcp(IRubyObject self, IRubyObject host, IRubyObject port) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(meta = true)
    public static IRubyObject udp(IRubyObject self, IRubyObject host, IRubyObject port) {
        throw new UnsupportedOperationException();
    }
    
    @JRubyMethod(meta = true, required = 1, optional = 1)
    public static IRubyObject unix(IRubyObject recv, IRubyObject[] args) {
        throw new UnsupportedOperationException();
    }
}
