/*
 * Copyright (C) 2024 Hideki Ikeda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.czeal.rfc3986;


import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import org.junit.jupiter.api.Test;


public class URIReferenceBuilderTest
{
    @Test
    public void test_fromURIReference_with_string()
    {
        URIReference uriRef1 = URIReferenceBuilder.fromURIReference("http://example.com").build();
        assertEquals("http://example.com", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("http", uriRef1.getScheme());
        Authority authority1 = uriRef1.getAuthority();
        assertEquals("example.com", authority1.toString());
        assertEquals(null, authority1.getUserinfo());
        Host host1 = authority1.getHost();
        assertEquals("example.com", host1.toString());
        assertEquals("example.com", host1.getValue());
        assertEquals(REGNAME, host1.getType());
        assertEquals(-1, authority1.getPort());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReferenceBuilder.fromURIReference("hTTp://example.com").build();;
        assertEquals("hTTp://example.com", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("hTTp", uriRef2.getScheme());
        Authority authority2 = uriRef2.getAuthority();
        assertEquals("example.com", authority2.toString());
        assertEquals(null, authority2.getUserinfo());
        Host host2 = authority2.getHost();
        assertEquals("example.com", host2.toString());
        assertEquals("example.com", host2.getValue());
        assertEquals(REGNAME, host2.getType());
        assertEquals(-1, authority2.getPort());
        assertEquals("", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = URIReferenceBuilder.fromURIReference("//example.com").build();;
        assertEquals("//example.com", uriRef3.toString());
        assertEquals(true, uriRef3.isRelativeReference());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals(null, uriRef3.getScheme());
        Authority authority = uriRef3.getAuthority();
        assertEquals("example.com", authority.toString());
        assertEquals(null, authority.getUserinfo());
        Host host = authority.getHost();
        assertEquals("example.com", host.toString());
        assertEquals("example.com", host.getValue());
        assertEquals(REGNAME, host.getType());
        assertEquals(-1, authority.getPort());
        assertEquals("", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = URIReferenceBuilder.fromURIReference("http:").setAuthorityRequired(false).build();;
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals(false, uriRef4.hasAuthority());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(null, uriRef4.getAuthority());
        assertEquals("", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = URIReferenceBuilder.fromURIReference("http://john@example.com").build();;
        assertEquals("http://john@example.com", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals(true, uriRef5.hasAuthority());
        assertEquals("http", uriRef5.getScheme());
        Authority authority5 = uriRef5.getAuthority();
        assertEquals("john@example.com", authority5.toString());
        assertEquals("john", authority5.getUserinfo());
        Host host5 = authority5.getHost();
        assertEquals("example.com", host5.toString());
        assertEquals("example.com", host5.getValue());
        assertEquals(REGNAME, host5.getType());
        assertEquals(-1, authority5.getPort());
        assertEquals("", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = URIReferenceBuilder.fromURIReference("http://%6A%6F%68%6E@example.com").build();;
        assertEquals("http://%6A%6F%68%6E@example.com", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("http", uriRef6.getScheme());
        Authority authority6 = uriRef6.getAuthority();
        assertEquals("%6A%6F%68%6E@example.com", authority6.toString());
        assertEquals("%6A%6F%68%6E", authority6.getUserinfo());
        Host host6 = authority6.getHost();
        assertEquals("example.com", host6.toString());
        assertEquals("example.com", host6.getValue());
        assertEquals(REGNAME, host6.getType());
        assertEquals(-1, authority6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = URIReferenceBuilder.fromURIReference("http://101.102.103.104").build();;
        assertEquals("http://101.102.103.104", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("http", uriRef7.getScheme());
        Authority authority7 = uriRef7.getAuthority();
        assertEquals("101.102.103.104", authority7.toString());
        assertEquals(null, authority7.getUserinfo());
        Host host7 = authority7.getHost();
        assertEquals("101.102.103.104", host7.toString());
        assertEquals("101.102.103.104", host7.getValue());
        assertEquals(HostType.IPV4, host7.getType());
        assertEquals(-1, authority7.getPort());
        assertEquals("", uriRef7.getPath());
        assertEquals(null, uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = URIReferenceBuilder.fromURIReference("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").build();;
        assertEquals("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("http", uriRef8.getScheme());
        Authority authority8 = uriRef8.getAuthority();
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", authority8.toString());
        assertEquals(null, authority8.getUserinfo());
        Host host8 = authority8.getHost();
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", host8.toString());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", host8.getValue());
        assertEquals(HostType.IPV6, host8.getType());
        assertEquals(-1, authority8.getPort());
        assertEquals("", uriRef8.getPath());
        assertEquals(null, uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = URIReferenceBuilder.fromURIReference("http://[2001:db8:0:1:1:1:1:1]").build();;
        assertEquals("http://[2001:db8:0:1:1:1:1:1]", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("http", uriRef9.getScheme());
        Authority authority9 = uriRef9.getAuthority();
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority9.toString());
        assertEquals(null, authority9.getUserinfo());
        Host host9 = authority9.getHost();
        assertEquals("[2001:db8:0:1:1:1:1:1]", host9.toString());
        assertEquals("[2001:db8:0:1:1:1:1:1]", host9.getValue());
        assertEquals(HostType.IPV6, host9.getType());
        assertEquals(-1, authority9.getPort());
        assertEquals("", uriRef9.getPath());
        assertEquals(null, uriRef9.getQuery());
        assertEquals(null, uriRef9.getFragment());

        URIReference uriRef10 = URIReferenceBuilder.fromURIReference("http://[2001:0:9d38:6abd:0:0:0:42]").build();;
        assertEquals("http://[2001:0:9d38:6abd:0:0:0:42]", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("http", uriRef10.getScheme());
        Authority authority10 = uriRef10.getAuthority();
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", authority10.toString());
        assertEquals(null, authority10.getUserinfo());
        Host host10 = authority10.getHost();
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", host10.toString());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", host10.getValue());
        assertEquals(HostType.IPV6, host10.getType());
        assertEquals(-1, authority10.getPort());
        assertEquals("", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals(null, uriRef10.getFragment());

        URIReference uriRef11 = URIReferenceBuilder.fromURIReference("http://[fe80::1]").build();;
        assertEquals("http://[fe80::1]", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("http", uriRef11.getScheme());
        Authority authority11 = uriRef11.getAuthority();
        assertEquals("[fe80::1]", authority11.toString());
        assertEquals(null, authority11.getUserinfo());
        Host host11 = authority11.getHost();
        assertEquals("[fe80::1]", host11.toString());
        assertEquals("[fe80::1]", host11.getValue());
        assertEquals(HostType.IPV6, host11.getType());
        assertEquals(-1, authority11.getPort());
        assertEquals("", uriRef11.getPath());
        assertEquals(null, uriRef11.getQuery());
        assertEquals(null, uriRef11.getFragment());

        URIReference uriRef12 = URIReferenceBuilder.fromURIReference("http://[2001:0:3238:DFE1:63::FEFB]").build();;
        assertEquals("http://[2001:0:3238:DFE1:63::FEFB]", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("http", uriRef12.getScheme());
        Authority authority12 = uriRef12.getAuthority();
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", authority12.toString());
        assertEquals(null, authority12.getUserinfo());
        Host host12 = authority12.getHost();
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", host12.toString());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", host12.getValue());
        assertEquals(HostType.IPV6, host12.getType());
        assertEquals(-1, authority12.getPort());
        assertEquals("", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = URIReferenceBuilder.fromURIReference("http://[v1.fe80::a+en1]").build();;
        assertEquals("http://[v1.fe80::a+en1]", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("http", uriRef13.getScheme());
        Authority authority13 = uriRef13.getAuthority();
        assertEquals("[v1.fe80::a+en1]", authority13.toString());
        assertEquals(null, authority13.getUserinfo());
        Host host13 = authority13.getHost();
        assertEquals("[v1.fe80::a+en1]", host13.toString());
        assertEquals("[v1.fe80::a+en1]", host13.getValue());
        assertEquals(HostType.IPVFUTURE, host13.getType());
        assertEquals(-1, authority13.getPort());
        assertEquals("", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = URIReferenceBuilder.fromURIReference("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").build();;
        assertEquals("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("http", uriRef14.getScheme());
        Authority authority14 = uriRef14.getAuthority();
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", authority14.toString());
        assertEquals(null, authority14.getUserinfo());
        Host host14 = authority14.getHost();
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", host14.toString());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", host14.getValue());
        assertEquals(REGNAME, host14.getType());
        assertEquals(-1, authority14.getPort());
        assertEquals("", uriRef14.getPath());
        assertEquals(null, uriRef14.getQuery());
        assertEquals(null, uriRef14.getFragment());

        URIReference uriRef15 = URIReferenceBuilder.fromURIReference("http://").build();;
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("http", uriRef15.getScheme());
        Authority authority15 = uriRef15.getAuthority();
        assertEquals(null, authority15.getUserinfo());
        Host host15 = authority15.getHost();
        assertEquals("", host15.getValue());
        assertEquals("", host15.toString());
        assertEquals(REGNAME, host15.getType());
        assertEquals(-1, authority15.getPort());
        assertEquals("", uriRef15.getPath());
        assertEquals(null, uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = URIReferenceBuilder.fromURIReference("http:///a").build();;
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("http", uriRef16.getScheme());
        Authority authority16 = uriRef16.getAuthority();
        assertEquals(null, authority16.getUserinfo());
        Host host16 = authority16.getHost();
        assertEquals("", host16.toString());
        assertEquals("", host16.getValue());
        assertEquals(REGNAME, host16.getType());
        assertEquals(-1, authority16.getPort());
        assertEquals("/a", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = URIReferenceBuilder.fromURIReference("http://example.com:80").build();;
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("http", uriRef17.getScheme());
        Authority authority17 = uriRef17.getAuthority();
        assertEquals(null, authority17.getUserinfo());
        Host host17 = authority17.getHost();
        assertEquals("example.com", host17.toString());
        assertEquals("example.com", host17.getValue());
        assertEquals(REGNAME, host17.getType());
        assertEquals(80, authority17.getPort());
        assertEquals("", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = URIReferenceBuilder.fromURIReference("http://example.com:").build();;
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("http", uriRef18.getScheme());
        Authority authority18 = uriRef18.getAuthority();
        assertEquals(null, authority18.getUserinfo());
        Host host18 = authority18.getHost();
        assertEquals("example.com", host18.toString());
        assertEquals("example.com", host18.getValue());
        assertEquals(REGNAME, host18.getType());
        assertEquals(-1, authority18.getPort());
        assertEquals("", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = URIReferenceBuilder.fromURIReference("http://example.com:001").build();;
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("http", uriRef19.getScheme());
        Authority authority19 = uriRef19.getAuthority();
        assertEquals(null, authority19.getUserinfo());
        Host host19 = authority19.getHost();
        assertEquals("example.com", host19.toString());
        assertEquals("example.com", host19.getValue());
        assertEquals(REGNAME, host19.getType());
        assertEquals(1, authority19.getPort());
        assertEquals("", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = URIReferenceBuilder.fromURIReference("http://example.com/a/b/c").build();;
        assertEquals("http://example.com/a/b/c", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("http", uriRef20.getScheme());
        Authority authority20 = uriRef20.getAuthority();
        assertEquals("example.com", authority20.toString());
        assertEquals(null, authority20.getUserinfo());
        Host host20 = authority20.getHost();
        assertEquals("example.com", host20.toString());
        assertEquals("example.com", host20.getValue());
        assertEquals(REGNAME, host20.getType());
        assertEquals(-1, authority20.getPort());
        assertEquals("/a/b/c", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = URIReferenceBuilder.fromURIReference("http://example.com/%61/%62/%63").build();;
        assertEquals("http://example.com/%61/%62/%63", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("http", uriRef21.getScheme());
        Authority authority21 = uriRef21.getAuthority();
        assertEquals("example.com", authority21.toString());
        assertEquals(null, authority21.getUserinfo());
        Host host21 = authority21.getHost();
        assertEquals("example.com", host21.toString());
        assertEquals("example.com", host21.getValue());
        assertEquals(REGNAME, host21.getType());
        assertEquals(-1, authority21.getPort());
        assertEquals("/%61/%62/%63", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = URIReferenceBuilder.fromURIReference("http:/a").setAuthorityRequired(false).build();;
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals(false, uriRef22.hasAuthority());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(null, uriRef22.getAuthority());
        assertEquals("/a", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = URIReferenceBuilder.fromURIReference("http:a").setAuthorityRequired(false).build();;
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals(false, uriRef23.hasAuthority());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(null, uriRef23.getAuthority());
        assertEquals("a", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = URIReferenceBuilder.fromURIReference("//").build();;
        assertEquals(true, uriRef24.isRelativeReference());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals(null, uriRef24.getScheme());
        Authority authority24 = uriRef24.getAuthority();
        assertEquals("", authority24.toString());
        assertEquals(null, authority24.getUserinfo());
        Host host24 = authority24.getHost();
        assertEquals("", host24.toString());
        assertEquals("", host24.getValue());
        assertEquals(REGNAME, host24.getType());
        assertEquals(-1, authority24.getPort());
        assertEquals("", uriRef24.getPath());
        assertEquals(null, uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        assertThrowsNPE(
            "The input string must not be null.",
            () -> URIReferenceBuilder.fromURIReference((String)null).build());
    }


    @Test
    public void test_fromURIReference_with_uriReference()
    {
        URIReference uriRef1 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com")).build();;
        assertEquals("http://example.com", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("http", uriRef1.getScheme());
        Authority authority1 = uriRef1.getAuthority();
        assertEquals("example.com", authority1.toString());
        assertEquals(null, authority1.getUserinfo());
        Host host1 = authority1.getHost();
        assertEquals("example.com", host1.toString());
        assertEquals("example.com", host1.getValue());
        assertEquals(REGNAME, host1.getType());
        assertEquals(-1, authority1.getPort());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReferenceBuilder.fromURIReference(URIReference.parse("hTTp://example.com")).build();
        assertEquals("hTTp://example.com", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("hTTp", uriRef2.getScheme());
        Authority authority2 = uriRef2.getAuthority();
        assertEquals("example.com", authority2.toString());
        assertEquals(null, authority2.getUserinfo());
        Host host2 = authority2.getHost();
        assertEquals("example.com", host2.toString());
        assertEquals("example.com", host2.getValue());
        assertEquals(REGNAME, host2.getType());
        assertEquals(-1, authority2.getPort());
        assertEquals("", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = URIReferenceBuilder.fromURIReference(URIReference.parse("//example.com")).build();
        assertEquals("//example.com", uriRef3.toString());
        assertEquals(true, uriRef3.isRelativeReference());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals(null, uriRef3.getScheme());
        Authority authority = uriRef3.getAuthority();
        assertEquals("example.com", authority.toString());
        assertEquals(null, authority.getUserinfo());
        Host host = authority.getHost();
        assertEquals("example.com", host.toString());
        assertEquals("example.com", host.getValue());
        assertEquals(REGNAME, host.getType());
        assertEquals(-1, authority.getPort());
        assertEquals("", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = URIReferenceBuilder.fromURIReference(URIReference.parse("http:")).setAuthorityRequired(false).build();
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals(false, uriRef4.hasAuthority());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(false, uriRef4.hasAuthority());
        assertEquals(null, uriRef4.getAuthority());
        assertEquals("", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://john@example.com")).build();
        assertEquals("http://john@example.com", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals(true, uriRef5.hasAuthority());
        assertEquals("http", uriRef5.getScheme());
        Authority authority5 = uriRef5.getAuthority();
        assertEquals("john@example.com", authority5.toString());
        assertEquals("john", authority5.getUserinfo());
        Host host5 = authority5.getHost();
        assertEquals("example.com", host5.toString());
        assertEquals("example.com", host5.getValue());
        assertEquals(REGNAME, host5.getType());
        assertEquals(-1, authority5.getPort());
        assertEquals("", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://%6A%6F%68%6E@example.com")).build();
        assertEquals("http://%6A%6F%68%6E@example.com", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("http", uriRef6.getScheme());
        Authority authority6 = uriRef6.getAuthority();
        assertEquals("%6A%6F%68%6E@example.com", authority6.toString());
        assertEquals("%6A%6F%68%6E", authority6.getUserinfo());
        Host host6 = authority6.getHost();
        assertEquals("example.com", host6.toString());
        assertEquals("example.com", host6.getValue());
        assertEquals(REGNAME, host6.getType());
        assertEquals(-1, authority6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://101.102.103.104")).build();
        assertEquals("http://101.102.103.104", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("http", uriRef7.getScheme());
        Authority authority7 = uriRef7.getAuthority();
        assertEquals("101.102.103.104", authority7.toString());
        assertEquals(null, authority7.getUserinfo());
        Host host7 = authority7.getHost();
        assertEquals("101.102.103.104", host7.toString());
        assertEquals("101.102.103.104", host7.getValue());
        assertEquals(HostType.IPV4, host7.getType());
        assertEquals(-1, authority7.getPort());
        assertEquals("", uriRef7.getPath());
        assertEquals(null, uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]")).build();
        assertEquals("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("http", uriRef8.getScheme());
        Authority authority8 = uriRef8.getAuthority();
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", authority8.toString());
        assertEquals(null, authority8.getUserinfo());
        Host host8 = authority8.getHost();
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", host8.toString());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", host8.getValue());
        assertEquals(HostType.IPV6, host8.getType());
        assertEquals(-1, authority8.getPort());
        assertEquals("", uriRef8.getPath());
        assertEquals(null, uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[2001:db8:0:1:1:1:1:1]")).build();
        assertEquals("http://[2001:db8:0:1:1:1:1:1]", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("http", uriRef9.getScheme());
        Authority authority9 = uriRef9.getAuthority();
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority9.toString());
        assertEquals(null, authority9.getUserinfo());
        Host host9 = authority9.getHost();
        assertEquals("[2001:db8:0:1:1:1:1:1]", host9.toString());
        assertEquals("[2001:db8:0:1:1:1:1:1]", host9.getValue());
        assertEquals(HostType.IPV6, host9.getType());
        assertEquals(-1, authority9.getPort());
        assertEquals("", uriRef9.getPath());
        assertEquals(null, uriRef9.getQuery());
        assertEquals(null, uriRef9.getFragment());

        URIReference uriRef10 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]")).build();
        assertEquals("http://[2001:0:9d38:6abd:0:0:0:42]", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("http", uriRef10.getScheme());
        Authority authority10 = uriRef10.getAuthority();
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", authority10.toString());
        assertEquals(null, authority10.getUserinfo());
        Host host10 = authority10.getHost();
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", host10.toString());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", host10.getValue());
        assertEquals(HostType.IPV6, host10.getType());
        assertEquals(-1, authority10.getPort());
        assertEquals("", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals(null, uriRef10.getFragment());

        URIReference uriRef11 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[fe80::1]")).build();
        assertEquals("http://[fe80::1]", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("http", uriRef11.getScheme());
        Authority authority11 = uriRef11.getAuthority();
        assertEquals("[fe80::1]", authority11.toString());
        assertEquals(null, authority11.getUserinfo());
        Host host11 = authority11.getHost();
        assertEquals("[fe80::1]", host11.toString());
        assertEquals("[fe80::1]", host11.getValue());
        assertEquals(HostType.IPV6, host11.getType());
        assertEquals(-1, authority11.getPort());
        assertEquals("", uriRef11.getPath());
        assertEquals(null, uriRef11.getQuery());
        assertEquals(null, uriRef11.getFragment());

        URIReference uriRef12 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]")).build();
        assertEquals("http://[2001:0:3238:DFE1:63::FEFB]", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("http", uriRef12.getScheme());
        Authority authority12 = uriRef12.getAuthority();
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", authority12.toString());
        assertEquals(null, authority12.getUserinfo());
        Host host12 = authority12.getHost();
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", host12.toString());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", host12.getValue());
        assertEquals(HostType.IPV6, host12.getType());
        assertEquals(-1, authority12.getPort());
        assertEquals("", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://[v1.fe80::a+en1]")).build();
        assertEquals("http://[v1.fe80::a+en1]", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("http", uriRef13.getScheme());
        Authority authority13 = uriRef13.getAuthority();
        assertEquals("[v1.fe80::a+en1]", authority13.toString());
        assertEquals(null, authority13.getUserinfo());
        Host host13 = authority13.getHost();
        assertEquals("[v1.fe80::a+en1]", host13.toString());
        assertEquals("[v1.fe80::a+en1]", host13.getValue());
        assertEquals(HostType.IPVFUTURE, host13.getType());
        assertEquals(-1, authority13.getPort());
        assertEquals("", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D")).build();
        assertEquals("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("http", uriRef14.getScheme());
        Authority authority14 = uriRef14.getAuthority();
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", authority14.toString());
        assertEquals(null, authority14.getUserinfo());
        Host host14 = authority14.getHost();
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", host14.toString());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", host14.getValue());
        assertEquals(REGNAME, host14.getType());
        assertEquals(-1, authority14.getPort());
        assertEquals("", uriRef14.getPath());
        assertEquals(null, uriRef14.getQuery());
        assertEquals(null, uriRef14.getFragment());

        URIReference uriRef15 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://")).build();
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("http", uriRef15.getScheme());
        Authority authority15 = uriRef15.getAuthority();
        assertEquals(null, authority15.getUserinfo());
        Host host15 = authority15.getHost();
        assertEquals("", host15.getValue());
        assertEquals("", host15.toString());
        assertEquals(REGNAME, host15.getType());
        assertEquals(-1, authority15.getPort());
        assertEquals("", uriRef15.getPath());
        assertEquals(null, uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = URIReferenceBuilder.fromURIReference(URIReference.parse("http:///a")).build();
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("http", uriRef16.getScheme());
        Authority authority16 = uriRef16.getAuthority();
        assertEquals(null, authority16.getUserinfo());
        Host host16 = authority16.getHost();
        assertEquals("", host16.toString());
        assertEquals("", host16.getValue());
        assertEquals(REGNAME, host16.getType());
        assertEquals(-1, authority16.getPort());
        assertEquals("/a", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com:80")).build();
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("http", uriRef17.getScheme());
        Authority authority17 = uriRef17.getAuthority();
        assertEquals(null, authority17.getUserinfo());
        Host host17 = authority17.getHost();
        assertEquals("example.com", host17.toString());
        assertEquals("example.com", host17.getValue());
        assertEquals(REGNAME, host17.getType());
        assertEquals(80, authority17.getPort());
        assertEquals("", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com:")).build();
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("http", uriRef18.getScheme());
        Authority authority18 = uriRef18.getAuthority();
        assertEquals(null, authority18.getUserinfo());
        Host host18 = authority18.getHost();
        assertEquals("example.com", host18.toString());
        assertEquals("example.com", host18.getValue());
        assertEquals(REGNAME, host18.getType());
        assertEquals(-1, authority18.getPort());
        assertEquals("", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com:001")).build();
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("http", uriRef19.getScheme());
        Authority authority19 = uriRef19.getAuthority();
        assertEquals(null, authority19.getUserinfo());
        Host host19 = authority19.getHost();
        assertEquals("example.com", host19.toString());
        assertEquals("example.com", host19.getValue());
        assertEquals(REGNAME, host19.getType());
        assertEquals(1, authority19.getPort());
        assertEquals("", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com/a/b/c")).build();
        assertEquals("http://example.com/a/b/c", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("http", uriRef20.getScheme());
        Authority authority20 = uriRef20.getAuthority();
        assertEquals("example.com", authority20.toString());
        assertEquals(null, authority20.getUserinfo());
        Host host20 = authority20.getHost();
        assertEquals("example.com", host20.toString());
        assertEquals("example.com", host20.getValue());
        assertEquals(REGNAME, host20.getType());
        assertEquals(-1, authority20.getPort());
        assertEquals("/a/b/c", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = URIReferenceBuilder.fromURIReference(URIReference.parse("http://example.com/%61/%62/%63")).build();
        assertEquals("http://example.com/%61/%62/%63", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("http", uriRef21.getScheme());
        Authority authority21 = uriRef21.getAuthority();
        assertEquals("example.com", authority21.toString());
        assertEquals(null, authority21.getUserinfo());
        Host host21 = authority21.getHost();
        assertEquals("example.com", host21.toString());
        assertEquals("example.com", host21.getValue());
        assertEquals(REGNAME, host21.getType());
        assertEquals(-1, authority21.getPort());
        assertEquals("/%61/%62/%63", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = URIReferenceBuilder.fromURIReference(URIReference.parse("http:/a")).setAuthorityRequired(false).build();
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals(false, uriRef22.hasAuthority());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(null, uriRef22.getAuthority());
        assertEquals("/a", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = URIReferenceBuilder.fromURIReference(URIReference.parse("http:a")).setAuthorityRequired(false).build();
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals(false, uriRef23.hasAuthority());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(null, uriRef23.getAuthority());
        assertEquals("a", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = URIReferenceBuilder.fromURIReference(URIReference.parse("//")).build();
        assertEquals(true, uriRef24.isRelativeReference());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals(null, uriRef24.getScheme());
        Authority authority24 = uriRef24.getAuthority();
        assertEquals("", authority24.toString());
        assertEquals(null, authority24.getUserinfo());
        Host host24 = authority24.getHost();
        assertEquals("", host24.toString());
        assertEquals("", host24.getValue());
        assertEquals(REGNAME, host24.getType());
        assertEquals(-1, authority24.getPort());
        assertEquals("", uriRef24.getPath());
        assertEquals(null, uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        assertThrowsNPE(
            "The input string must not be null.",
            () -> URIReferenceBuilder.fromURIReference(URIReference.parse((String)null)).build());
    }


    @Test
    public void test_setAuthorityRequired()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setAuthorityRequired(true)
            .build();
        assertEquals("http://example.com", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("http", uriRef1.getScheme());
        Authority authority1 = uriRef1.getAuthority();
        assertEquals("example.com", authority1.toString());
        assertEquals(null, authority1.getUserinfo());
        Host host1 = authority1.getHost();
        assertEquals("example.com", host1.toString());
        assertEquals("example.com", host1.getValue());
        assertEquals(REGNAME, host1.getType());
        assertEquals(-1, authority1.getPort());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setAuthorityRequired(false)
            .build();
        assertEquals("http:", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals(false, uriRef2.hasAuthority());
        assertEquals("http", uriRef2.getScheme());
        assertEquals(null, uriRef2.getAuthority());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());
    }


    @Test
    public void test_setScheme()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setScheme("ftp")
            .build();
        assertEquals("ftp", uriRef1.getScheme());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setScheme("https")
            .build();
        assertEquals("https", uriRef2.getScheme());

        URIReference uriRef3 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setScheme(null)
            .build();
        assertEquals(null, uriRef3.getScheme());
    }


    @Test
    public void test_setHost()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("example2.com")
            .build();
        assertEquals(REGNAME, uriRef1.getHost().getType());
        assertEquals("example2.com", uriRef1.getHost().getValue());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("101.102.103.104")
            .build();
        assertEquals(IPV4, uriRef2.getHost().getType());
        assertEquals("101.102.103.104", uriRef2.getHost().getValue());

        URIReference uriRef3 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]")
            .build();
        assertEquals(IPV6, uriRef3.getHost().getType());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef3.getHost().getValue());

        URIReference uriRef4 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[2001:db8:0:1:1:1:1:1]")
            .build();
        assertEquals(IPV6, uriRef4.getHost().getType());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef4.getHost().getValue());

        URIReference uriRef5 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[2001:0:9d38:6abd:0:0:0:42]")
            .build();
        assertEquals(IPV6, uriRef5.getHost().getType());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef5.getHost().getValue());

        URIReference uriRef6 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[fe80::1]")
            .build();
        assertEquals(IPV6, uriRef6.getHost().getType());
        assertEquals("[fe80::1]", uriRef6.getHost().getValue());

        URIReference uriRef7 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[2001:0:3238:DFE1:63::FEFB]")
            .build();
        assertEquals(IPV6, uriRef7.getHost().getType());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef7.getHost().getValue());

        URIReference uriRef8 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("[v1.fe80::a+en1]")
            .build();
        assertEquals(IPVFUTURE, uriRef8.getHost().getType());
        assertEquals("[v1.fe80::a+en1]", uriRef8.getHost().getValue());

        URIReference uriRef9 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("%65%78%61%6D%70%6C%65%2E%63%6F%6D")
            .build();
        assertEquals(REGNAME, uriRef9.getHost().getType());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef9.getHost().getValue());

        URIReference uriRef10 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost("")
            .build();
        assertEquals(REGNAME, uriRef10.getHost().getType());
        assertEquals("", uriRef10.getHost().getValue());

        URIReference uriRef11 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setHost(null)
            .build();
        assertEquals(REGNAME, uriRef11.getHost().getType());
        assertEquals(null, uriRef11.getHost().getValue());
    }


    @Test
    public void test_setPath()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setPath("/a")
            .build();
        assertEquals("/a", uriRef1.getPath());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setPath("/a/b")
            .build();
        assertEquals("/a/b", uriRef2.getPath());

        URIReference uriRef3 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setPath("/")
            .build();
        assertEquals("/", uriRef3.getPath());

        URIReference uriRef4 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setPath("")
            .build();
        assertEquals("", uriRef4.getPath());

        URIReference uriRef5 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .setPath(null)
            .build();
        assertEquals(null, uriRef5.getPath());
    }


    @Test
    public void test_setPathSegments()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendPathSegments("a", "b", "c")
            .build();
        assertEquals("/a/b/c", uriRef1.getPath());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendPathSegments("")
            .build();
        assertEquals("/", uriRef2.getPath());

        assertThrowsNPE("A segment must not be null.", () -> URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendPathSegments((String)null)
            .build());
    }


    @Test
    public void test_appendQueryParam()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendQueryParam("k", "v")
            .build();
        assertEquals("k=v", uriRef1.getQuery());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendQueryParam("k1", "v1")
            .appendQueryParam("k2", "v2")
            .build();
        assertEquals("k1=v1&k2=v2", uriRef2.getQuery());

        URIReference uriRef3 = URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendQueryParam("", "")
            .build();
        assertEquals("=", uriRef3.getQuery());

        assertThrowsNPE("The key must not be null.", () -> URIReferenceBuilder
            .fromURIReference("http://example.com")
            .appendQueryParam(null, null));
    }


    @Test
    public void test_replaceQueryParam()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com?k=v")
            .replaceQueryParam("k", "w")
            .build();
        assertEquals("k=w", uriRef1.getQuery());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com?k=v")
            .replaceQueryParam("k", null)
            .build();
        assertEquals("k", uriRef2.getQuery());

        assertThrowsNPE("The key must not be null.", () -> URIReferenceBuilder
            .fromURIReference("http://example.com?k=v")
            .appendQueryParam(null, "w"));
    }


    @Test
    public void test_removeQueryParam()
    {
        URIReference uriRef1 = URIReferenceBuilder
            .fromURIReference("http://example.com?k=v")
            .removeQueryParam("k")
            .build();
        assertEquals(null, uriRef1.getQuery());

        URIReference uriRef2 = URIReferenceBuilder
            .fromURIReference("http://example.com?k=v")
            .removeQueryParam(null)
            .build();
        assertEquals("k=v", uriRef2.getQuery());
    }


    @Test
    public void test_setQuery()
    {
        URIReference uriRef1 = URIReferenceBuilder.fromURIReference("http://example.com").setQuery("k=v").build();
        assertEquals("k=v", uriRef1.getQuery());

        URIReference uriRef2 = URIReferenceBuilder.fromURIReference("http://example.com").setQuery("k=").build();
        assertEquals("k=", uriRef2.getQuery());

        URIReference uriRef3 = URIReferenceBuilder.fromURIReference("http://example.com").setQuery("k").build();
        assertEquals("k", uriRef3.getQuery());

        URIReference uriRef4 = URIReferenceBuilder.fromURIReference("http://example.com").setQuery("").build();
        assertEquals("", uriRef4.getQuery());

        URIReference uriRef5 = URIReferenceBuilder.fromURIReference("http://example.com").setQuery(null).build();
        assertEquals(null, uriRef5.getQuery());
    }


    @Test
    public void test_setFragment()
    {
        URIReference uriRef1 = URIReferenceBuilder.fromURIReference("http://example.com").setFragment("section1").build();
        assertEquals("section1", uriRef1.getFragment());

        URIReference uriRef2 = URIReferenceBuilder.fromURIReference("http://example.com").setFragment("fig%20A").build();
        assertEquals("fig%20A", uriRef2.getFragment());

        URIReference uriRef3 = URIReferenceBuilder.fromURIReference("http://example.com").setFragment("2.3").build();
        assertEquals("2.3", uriRef3.getFragment());

        URIReference uriRef4 = URIReferenceBuilder.fromURIReference("http://example.com").setFragment("").build();
        assertEquals("", uriRef4.getFragment());

        URIReference uriRef5 = URIReferenceBuilder.fromURIReference("http://example.com").setFragment(null).build();
        assertEquals(null, uriRef5.getFragment());
    }
}
