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


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import org.junit.jupiter.api.Test;


public class AuthorityBuilderTest
{
    @Test
    public void test_build()
    {
        Authority authority1 = new AuthorityBuilder()
            .setCharset(UTF_8).setUserinfo("john").setHost("example.com").setPort(80).build();
        assertEquals("john", authority1.getUserinfo());
        assertEquals(REGNAME, authority1.getHost().getType());
        assertEquals("example.com", authority1.getHost().getValue());
        assertEquals(80, authority1.getPort());
        assertEquals("john@example.com:80", authority1.toString());

        Authority authority2 = new AuthorityBuilder()
            .setCharset(UTF_8).setHost("example.com").setPort(80).build();
        assertEquals(null, authority2.getUserinfo());
        assertEquals(REGNAME, authority2.getHost().getType());
        assertEquals("example.com", authority2.getHost().getValue());
        assertEquals(80, authority2.getPort());
        assertEquals("example.com:80", authority2.toString());

        Authority authority3 = new AuthorityBuilder()
            .setCharset(UTF_8).setPort(80).build();
        assertEquals(null, authority3.getUserinfo());
        assertEquals(REGNAME, authority3.getHost().getType());
        assertEquals(null, authority3.getHost().getValue());
        assertEquals(80, authority3.getPort());
        assertEquals(":80", authority3.toString());

        Authority authority4 = new AuthorityBuilder()
            .setCharset(UTF_8).build();
        assertEquals(null, authority4.getUserinfo());
        assertEquals(REGNAME, authority3.getHost().getType());
        assertEquals(null, authority3.getHost().getValue());
        assertEquals(-1, authority4.getPort());
        assertEquals("", authority4.toString());

        Authority authority5 = new AuthorityBuilder()
            .setCharset(UTF_8).setUserinfo("john").setHost("101.102.103.104").setPort(80).build();
        assertEquals("john", authority5.getUserinfo());
        assertEquals(IPV4, authority5.getHost().getType());
        assertEquals("101.102.103.104", authority5.getHost().getValue());
        assertEquals(80, authority5.getPort());
        assertEquals("john@101.102.103.104:80", authority5.toString());

        Authority authority6 = new AuthorityBuilder()
            .setCharset(UTF_8).setUserinfo("john").setHost("101.102.103.104").setPort(80).build();
        assertEquals("john", authority6.getUserinfo());
        assertEquals(IPV4, authority6.getHost().getType());
        assertEquals("101.102.103.104", authority6.getHost().getValue());
        assertEquals(80, authority6.getPort());
        assertEquals("john@101.102.103.104:80", authority6.toString());

        Authority authority7 = new AuthorityBuilder()
            .setCharset(UTF_8).setUserinfo("john").setHost("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").setPort(80).build();
        assertEquals("john", authority7.getUserinfo());
        assertEquals(IPV6, authority7.getHost().getType());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", authority7.getHost().getValue());
        assertEquals(80, authority7.getPort());
        assertEquals("john@[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]:80", authority7.toString());

        Authority authority8 = new AuthorityBuilder()
            .setCharset(UTF_8).setUserinfo("john").setHost("[v1.fe80::a+en1]").setPort(80).build();
        assertEquals("john", authority8.getUserinfo());
        assertEquals(IPVFUTURE, authority8.getHost().getType());
        assertEquals("[v1.fe80::a+en1]", authority8.getHost().getValue());
        assertEquals(80, authority8.getPort());
        assertEquals("john@[v1.fe80::a+en1]:80", authority8.toString());

        assertThrowsIAE(
            "The userinfo value \"?\" has an invalid character \"?\" at the index 0.",
            () -> new AuthorityBuilder().setCharset(UTF_8).setUserinfo("?").build());

        assertThrowsIAE(
            "The userinfo value \"%XX\" has an invalid hex digit \"X\" at the index 1.",
            () -> new AuthorityBuilder().setCharset(UTF_8).setUserinfo("%XX").build());
    }
}
