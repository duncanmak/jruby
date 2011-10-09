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

import static jnr.constants.platform.AddressFamily.AF_INET;
import static jnr.constants.platform.AddressFamily.AF_INET6;
import static jnr.constants.platform.IPProto.IPPROTO_TCP;
import static jnr.constants.platform.IPProto.IPPROTO_UDP;
import static jnr.constants.platform.NameInfo.NI_NUMERICHOST;
import static jnr.constants.platform.NameInfo.NI_NUMERICSERV;
import static jnr.constants.platform.ProtocolFamily.PF_INET;
import static jnr.constants.platform.ProtocolFamily.PF_INET6;
import static jnr.constants.platform.Sock.SOCK_DGRAM;
import static jnr.constants.platform.Sock.SOCK_STREAM;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyObject;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

@JRubyClass(name = "Addrinfo")
public class Addrinfo extends RubyObject {

    private static final ObjectAllocator ADDRINFO_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new Addrinfo(runtime, klass);
        }
    };

    static void createAddrinfo(Ruby runtime) {
        RubyClass result = runtime.defineClass("Addrinfo", runtime.getObject(), ADDRINFO_ALLOCATOR);
        result.defineAnnotatedMethods(Addrinfo.class);
    }

    public Addrinfo(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
    }

    public Addrinfo(Ruby runtime, InetAddress address, int port, int family, int pfamily, int protocol, int socktype) {
        super(runtime, runtime.getClass("Addrinfo"));
        this.address  = address;
        this.port     = port;
        this.family   = family;
        this.pfamily  = pfamily;
        this.protocol = protocol;
        this.socktype = socktype;
    }

    private InetAddress address;
    private int port;
    private int family;
    private int pfamily;
    private int protocol;
    private int socktype;

    @JRubyMethod(meta = true, rest = true, required = 2, optional = 4)
    public static IRubyObject foreach(IRubyObject self, IRubyObject[] args, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(meta = true, rest = true, required = 2, optional = 4)
    public static IRubyObject getaddrinfo(IRubyObject self, IRubyObject[] args, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(meta = true)
    public static IRubyObject ip(IRubyObject self, IRubyObject arg) {
        Ruby runtime = self.getRuntime();
        try {
            InetAddress host = InetAddress.getByName(arg.convertToString().toString());
            int port     = 0;
            int family   = AF_INET.intValue();
            int pfamily  = PF_INET.intValue();
            int protocol = 0;
            int socktype = 0;

            return new Addrinfo(runtime, host, port, family, pfamily, protocol, socktype);
        } catch (UnknownHostException e) {
            throw new RaiseException(
                runtime, runtime.getClass("SocketError"), "getaddrinfo: Name or service not known", true);
        }
    }

    // TODO; Implement #new

    @JRubyMethod(meta = true)
    public static IRubyObject tcp(IRubyObject self, IRubyObject arg0, IRubyObject arg1) {
        Ruby runtime = self.getRuntime();

        try {
            InetAddress host = InetAddress.getByName(arg0.convertToString().toString());
            int port     = RubyNumeric.num2int(arg1);
            int family   = AF_INET.intValue();
            int pfamily  = PF_INET.intValue();
            int protocol = IPPROTO_TCP.intValue();
            int socktype = SOCK_STREAM.intValue();

            return new Addrinfo(runtime, host, port, family, pfamily, protocol, socktype);

        } catch (UnknownHostException e) {
            throw new RaiseException(
                runtime, runtime.getClass("SocketError"), "getaddrinfo: Name or service not known", true);
        }
    }

    @JRubyMethod(meta = true)
    public static IRubyObject udp(IRubyObject self, IRubyObject arg0, IRubyObject arg1) {
        Ruby runtime = self.getRuntime();

        try {
            InetAddress host = InetAddress.getByName(arg0.convertToString().toString());
            int port     = RubyNumeric.num2int(arg1);
            int family   = AF_INET.intValue();
            int pfamily  = PF_INET.intValue();
            int protocol = IPPROTO_UDP.intValue();
            int socktype = SOCK_DGRAM.intValue();

            return new Addrinfo(runtime, host, port, family, pfamily, protocol, socktype);

        } catch (UnknownHostException e) {
            throw new RaiseException(
                runtime, runtime.getClass("SocketError"), "getaddrinfo: Name or service not known", true);
        }
    }

    @JRubyMethod(meta = true, required = 1, optional = 1)
    public static IRubyObject unix(IRubyObject recv, IRubyObject[] args) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public RubyNumeric afamily(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), family);
    }

    @JRubyMethod
    public void bind(ThreadContext ctx, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject canonname(ThreadContext ctx) {
        return RubyString.newString(ctx.getRuntime(), address.getCanonicalHostName());
    }

    @JRubyMethod
    public void connect(ThreadContext ctx, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(rest = true)
    public IRubyObject connect_from(ThreadContext ctx, IRubyObject[] args, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(rest = true)
    public IRubyObject connect_to(ThreadContext ctx, IRubyObject[] args, Block block) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(rest = true)
    public IRubyObject family_addrinfo(ThreadContext ctx, IRubyObject[] args) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject getnameinfo(ThreadContext ctx) { return getnameinfo(ctx, 0); }

    @JRubyMethod
    public IRubyObject getnameinfo(ThreadContext ctx, IRubyObject flags) {
        return getnameinfo(ctx, flags.isNil() ? 0 : RubyNumeric.num2int(flags));
    }

    IRubyObject getnameinfo(ThreadContext ctx, int flags) {
        IRubyObject host = ip_address(ctx);
        IRubyObject port = RubyString.newString(ctx.getRuntime(), Integer.toString(this.port));
        return RubyArray.newArrayLight(ctx.getRuntime(), host, port);
    }

    @JRubyMethod
    public IRubyObject inspect(ThreadContext ctx) {
        // TODO: Do better here
        return RubyString.newString(ctx.getRuntime(), address.toString ());
    }

    @JRubyMethod
    public IRubyObject inspect_sockaddr(ThreadContext ctx) {
        String s = String.format("%s:%d", address.getHostAddress(), port);
        return RubyString.newString(ctx.getRuntime(), s);
    }

    @JRubyMethod(name = "ip?")
    public IRubyObject is_ip(ThreadContext ctx) {
        // TODO: Support Unix Domain Sockets for later
        return RubyBoolean.newBoolean(ctx.getRuntime(), true);
    }

    @JRubyMethod
    public IRubyObject ip_address(ThreadContext ctx) {
        // TODO: Support Unix Domain Sockets for later
        return RubyString.newString(ctx.getRuntime(), address.getHostAddress());
    }

    @JRubyMethod
    public IRubyObject ip_port(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), port);
    }

    @JRubyMethod
    public IRubyObject ip_unpack(ThreadContext ctx) {
        return RubyArray.newArrayLight(ctx.getRuntime(), ip_address(ctx), ip_port(ctx));
    }

    @JRubyMethod(name = "ipv4?")
    public IRubyObject is_ipv4(ThreadContext ctx) {
        boolean result = address instanceof Inet4Address;
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv4_loopback?")
    public IRubyObject is_ipv4_loopback(ThreadContext ctx) {
        boolean ipv4   = address instanceof Inet4Address;
        boolean result = ipv4 && address.isLoopbackAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv4_multicast?")
    public IRubyObject is_ipv4_multicast(ThreadContext ctx) {
        boolean ipv4   = address instanceof Inet4Address;
        boolean result = ipv4 && address.isMulticastAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv4_private?")
    public IRubyObject is_ipv4_private(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(name = "ipv6?")
    public IRubyObject is_ipv6(ThreadContext ctx) {
        boolean result = address instanceof Inet6Address;
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_linklocal?")
    public IRubyObject is_ipv6_linklocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isLinkLocalAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_loopback?")
    public IRubyObject is_ipv6_loopback(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isLoopbackAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_mc_global?")
    public IRubyObject is_ipv6_mc_global(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMCGlobal();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_mc_linklocal?")
    public IRubyObject is_ipv6_mc_linklocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMCLinkLocal();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_mc_nodelocal?")
    public IRubyObject is_ipv6_mc_nodelocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMCNodeLocal();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_mc_orglocal?")
    public IRubyObject is_ipv6_mc_orglocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMCOrgLocal();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_mc_sitelocal?")
    public IRubyObject is_ipv6_mc_sitelocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMCSiteLocal();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_multicast?")
    public IRubyObject is_ipv6_multicast(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isMulticastAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod(name = "ipv6_sitelocal?")
    public IRubyObject is_ipv6_sitelocal(ThreadContext ctx) {
        boolean ipv6   = address instanceof Inet6Address;
        boolean result = ipv6 && address.isSiteLocalAddress();
        return RubyBoolean.newBoolean(ctx.getRuntime(), result);
    }

    @JRubyMethod
    public IRubyObject ipv6_to_ipv4(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(name = "ipv6_unspecified?")
    public IRubyObject is_ipv6_unspecified(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(name = "ipv6_v4compat?")
    public IRubyObject is_ipv6_v4compat(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(name = "ipv6_v4mapped?")
    public IRubyObject is_ipv6_v4mapped(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject listen(ThreadContext ctx, Block block) {
        IRubyObject backlog = RubyNumeric.int2fix(ctx.getRuntime(), 5);
        return listen(ctx, backlog, block);
    }

    @JRubyMethod
    public IRubyObject listen(ThreadContext ctx, IRubyObject arg0, Block block) {
        int backlog = RubyNumeric.fix2int(arg0);
        throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject pfamily(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), pfamily);
    }

    @JRubyMethod
    public IRubyObject protocol(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), protocol);
    }

    @JRubyMethod
    public IRubyObject socktype(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), socktype);
    }

    @JRubyMethod(name = {"to_s", "to_str"})
    public IRubyObject to_s(ThreadContext ctx) {
        InetSocketAddress sock = new InetSocketAddress(address, port);
        return RubySocket.pack_sockaddr_in(ctx, sock);
    }

    @JRubyMethod
    public IRubyObject to_sockaddr(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }

    @JRubyMethod(name = "unix?")
    public IRubyObject is_unix(ThreadContext ctx) {
        // TODO: Unsupported for now
        return RubyBoolean.newBoolean(ctx.getRuntime(), false);
    }

    @JRubyMethod
    public IRubyObject unix_path(ThreadContext ctx) {
        throw new UnsupportedOperationException();
    }
}
