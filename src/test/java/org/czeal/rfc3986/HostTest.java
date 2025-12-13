/*
 * Copyright (C) 2024-2025 Hideki Ikeda
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


import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import org.junit.jupiter.api.Test;


public class HostTest
{
    @Test
    public void test_parse()
    {
        assertDoesNotThrow(() -> Host.parse("example.com"));
        assertDoesNotThrow(() -> Host.parse("101.102.103.104"));
        assertDoesNotThrow(() -> Host.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"));
        assertDoesNotThrow(() -> Host.parse("[2001:db8:0:1:1:1:1:1]"));
        assertDoesNotThrow(() -> Host.parse("[2001:0:9d38:6abd:0:0:0:42]"));
        assertDoesNotThrow(() -> Host.parse("[fe80::1]"));
        assertDoesNotThrow(() -> Host.parse("[2001:0:3238:DFE1:63::FEFB]"));
        assertDoesNotThrow(() -> Host.parse("[v1.fe80::a+en1]"));
        assertDoesNotThrow(() -> Host.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D"));
        assertDoesNotThrow(() -> Host.parse(""));
        assertDoesNotThrow(() -> Host.parse(null));

        assertThrowsIAE(
            "The host value \"例子.测试\" has an invalid character \"例\" at the index 0.",
            () -> Authority.parse("例子.测试"));

        assertThrowsIAE(
            "The host value \"%XX\" has an invalid hex digit \"X\" at the index 1.",
            () -> Authority.parse("%XX"));
    }


    @Test
    public void test_getType()
    {
        assertEquals(REGNAME, Host.parse("example.com").getType());
        assertEquals(IPV4, Host.parse("101.102.103.104").getType());
        assertEquals(IPV6, Host.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getType());
        assertEquals(IPV6, Host.parse("[2001:db8:0:1:1:1:1:1]").getType());
        assertEquals(IPV6, Host.parse("[2001:0:9d38:6abd:0:0:0:42]").getType());
        assertEquals(IPV6, Host.parse("[fe80::1]").getType());
        assertEquals(IPV6, Host.parse("[2001:0:3238:DFE1:63::FEFB]").getType());
        assertEquals(IPVFUTURE, Host.parse("[v1.fe80::a+en1]").getType());
        assertEquals(REGNAME, Host.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").getType());
        assertEquals(REGNAME, Host.parse("").getType());
        assertEquals(REGNAME, Host.parse(null).getType());
    }


    @Test
    public void test_getValue()
    {
        assertEquals("example.com", Host.parse("example.com").getValue());
        assertEquals("101.102.103.104", Host.parse("101.102.103.104").getValue());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", Host.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getValue());
        assertEquals("[2001:db8:0:1:1:1:1:1]", Host.parse("[2001:db8:0:1:1:1:1:1]").getValue());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", Host.parse("[2001:0:9d38:6abd:0:0:0:42]").getValue());
        assertEquals("[fe80::1]", Host.parse("[fe80::1]").getValue());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", Host.parse("[2001:0:3238:DFE1:63::FEFB]").getValue());
        assertEquals("[v1.fe80::a+en1]", Host.parse("[v1.fe80::a+en1]").getValue());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", Host.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").getValue());
        assertEquals("", Host.parse("").getValue());
        assertEquals((String)null, Host.parse(null).getValue());
    }


    @Test
    public void test_equals()
    {
        assertFalse(Host.parse("FB").equals(Host.parse("Ea")));
    }


    @Test
    public void test_compareTo()
    {
        assertEquals(0, Host.parse("example.com").compareTo(Host.parse("example.com")));

        assertTrue(Host.parse("127.0.0.1").compareTo(Host.parse("example.com")) < 0);

        assertThrowsNPE("A null value is not comparable.", () -> Host.parse("example.com").compareTo(null));
    }
}
