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


public class HostParserTest
{
    @Test
    public void test_parse()
    {
        Host host1 = new HostParser().parse("example.com", UTF_8);
        assertEquals(REGNAME, host1.getType());
        assertEquals("example.com", host1.getValue());

        Host host2 = new HostParser().parse("101.102.103.104", UTF_8);
        assertEquals(IPV4, host2.getType());
        assertEquals("101.102.103.104", host2.getValue());

        Host host3 = new HostParser().parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", UTF_8);
        assertEquals(IPV6, host3.getType());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", host3.getValue());

        Host host4 = new HostParser().parse("[2001:db8:0:1:1:1:1:1]", UTF_8);
        assertEquals(IPV6, host4.getType());
        assertEquals("[2001:db8:0:1:1:1:1:1]", host4.getValue());

        Host host5 = new HostParser().parse("[2001:0:9d38:6abd:0:0:0:42]", UTF_8);
        assertEquals(IPV6, host5.getType());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", host5.getValue());

        Host host6 = new HostParser().parse("[fe80::1]", UTF_8);
        assertEquals(IPV6, host6.getType());
        assertEquals("[fe80::1]", host6.getValue());

        Host host7 = new HostParser().parse("[2001:0:3238:DFE1:63::FEFB]", UTF_8);
        assertEquals(IPV6, host7.getType());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", host7.getValue());

        Host host8 = new HostParser().parse("[v1.fe80::a+en1]", UTF_8);
        assertEquals(IPVFUTURE, host8.getType());
        assertEquals("[v1.fe80::a+en1]", host8.getValue());

        Host host9 = new HostParser().parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D", UTF_8);
        assertEquals(REGNAME, host9.getType());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", host9.getValue());

        Host host10 = new HostParser().parse("", UTF_8);
        assertEquals(REGNAME, host10.getType());
        assertEquals("", host10.getValue());

        Host host11 = new HostParser().parse(null, UTF_8);
        assertEquals(REGNAME, host11.getType());
        assertEquals(null, host11.getValue());

        assertThrowsIAE(
            "The host value \"例子.测试\" has an invalid character \"例\" at the index 0.",
            () -> new HostParser().parse("例子.测试", UTF_8));

        assertThrowsIAE(
            "The host value \"%XX\" has an invalid hex digit \"X\" at the index 1.",
            () -> new HostParser().parse("%XX", UTF_8));
    }
}
