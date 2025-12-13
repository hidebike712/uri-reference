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


public class AuthorityParserTest
{
    @Test
    public void test_parse()
    {
        Authority authority1 = new AuthorityParser().parse("example.com", UTF_8);
        assertEquals(null, authority1.getUserinfo());
        assertEquals(REGNAME, authority1.getHost().getType());
        assertEquals("example.com", authority1.getHost().getValue());
        assertEquals(-1, authority1.getPort());
        assertEquals("example.com", authority1.toString());

        Authority authority2 = new AuthorityParser().parse("john@example.com:80", UTF_8);
        assertEquals("john", authority2.getUserinfo());
        assertEquals(REGNAME, authority2.getHost().getType());
        assertEquals("example.com", authority2.getHost().getValue());
        assertEquals(80, authority2.getPort());
        assertEquals("john@example.com:80", authority2.toString());

        Authority authority3 = new AuthorityParser().parse("example.com:001", UTF_8);
        assertEquals(null, authority3.getUserinfo());
        assertEquals(REGNAME, authority3.getHost().getType());
        assertEquals("example.com", authority3.getHost().getValue());
        assertEquals(1, authority3.getPort());
        assertEquals("example.com:1", authority3.toString());

        Authority authority4 = new AuthorityParser().parse("%6A%6F%68%6E@example.com", UTF_8);
        assertEquals("%6A%6F%68%6E", authority4.getUserinfo());
        assertEquals(REGNAME, authority4.getHost().getType());
        assertEquals("example.com", authority4.getHost().getValue());
        assertEquals(-1, authority4.getPort());
        assertEquals("%6A%6F%68%6E@example.com", authority4.toString());

        Authority authority5 = new AuthorityParser().parse("101.102.103.104", UTF_8);
        assertEquals(null, authority5.getUserinfo());
        assertEquals(IPV4, authority5.getHost().getType());
        assertEquals("101.102.103.104", authority5.getHost().getValue());
        assertEquals(-1, authority5.getPort());
        assertEquals("101.102.103.104", authority5.toString());

        Authority authority6 = new AuthorityParser().parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", UTF_8);
        assertEquals(null, authority6.getUserinfo());
        assertEquals(IPV6, authority6.getHost().getType());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", authority6.getHost().getValue());
        assertEquals(-1, authority6.getPort());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", authority6.toString());

        Authority authority7 = new AuthorityParser().parse("[2001:db8:0:1:1:1:1:1]", UTF_8);
        assertEquals(null, authority7.getUserinfo());
        assertEquals(IPV6, authority7.getHost().getType());
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority7.getHost().getValue());
        assertEquals(-1, authority7.getPort());
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority7.toString());

        Authority authority8 = new AuthorityParser().parse("[2001:db8:0:1:1:1:1:1]", UTF_8);
        assertEquals(null, authority8.getUserinfo());
        assertEquals(IPV6, authority8.getHost().getType());
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority8.getHost().getValue());
        assertEquals(-1, authority8.getPort());
        assertEquals("[2001:db8:0:1:1:1:1:1]", authority8.toString());

        Authority authority9 = new AuthorityParser().parse("[2001:0:9d38:6abd:0:0:0:42]", UTF_8);
        assertEquals(null, authority9.getUserinfo());
        assertEquals(IPV6, authority9.getHost().getType());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", authority9.getHost().getValue());
        assertEquals(-1, authority9.getPort());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", authority9.toString());

        Authority authority10 = new AuthorityParser().parse("[fe80::1]", UTF_8);
        assertEquals(null, authority10.getUserinfo());
        assertEquals(IPV6, authority10.getHost().getType());
        assertEquals("[fe80::1]", authority10.getHost().getValue());
        assertEquals(-1, authority10.getPort());
        assertEquals("[fe80::1]", authority10.toString());

        Authority authority11 = new AuthorityParser().parse("[2001:0:3238:DFE1:63::FEFB]", UTF_8);
        assertEquals(null, authority11.getUserinfo());
        assertEquals(IPV6, authority11.getHost().getType());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", authority11.getHost().getValue());
        assertEquals(-1, authority11.getPort());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", authority11.toString());

        Authority authority12 = new AuthorityParser().parse("[v1.fe80::a+en1]", UTF_8);
        assertEquals(null, authority12.getUserinfo());
        assertEquals(IPVFUTURE, authority12.getHost().getType());
        assertEquals("[v1.fe80::a+en1]", authority12.getHost().getValue());
        assertEquals(-1, authority12.getPort());
        assertEquals("[v1.fe80::a+en1]", authority12.toString());

        Authority authority13 = new AuthorityParser().parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D", UTF_8);
        assertEquals(null, authority13.getUserinfo());
        assertEquals(REGNAME, authority13.getHost().getType());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", authority13.getHost().getValue());
        assertEquals(-1, authority13.getPort());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", authority13.toString());

        Authority authority14 = new AuthorityParser().parse("", UTF_8);
        assertEquals(null, authority14.getUserinfo());
        assertEquals(REGNAME, authority14.getHost().getType());
        assertEquals("", authority14.getHost().getValue());
        assertEquals(-1, authority14.getPort());
        assertEquals("", authority14.toString());

        assertThrowsIAE(
            "The port value \"password@example.com\" has an invalid character \"p\" at the index 0.",
            () -> Authority.parse("user@name:password@example.com", UTF_8));

        assertThrowsIAE(
            "The userinfo value \"müller\" has an invalid character \"ü\" at the index 1.",
            () -> Authority.parse("müller@example.com", UTF_8));

        assertThrowsIAE(
            "The host value \"%XX\" has an invalid hex digit \"X\" at the index 1.",
            () -> Authority.parse("%XX", UTF_8));
    }
}
