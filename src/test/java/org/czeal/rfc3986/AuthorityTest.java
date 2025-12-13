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


public class AuthorityTest
{
    @Test
    public void test_parse()
    {
        assertDoesNotThrow(() -> Authority.parse("example.com"));
        assertDoesNotThrow(() -> Authority.parse("john@example.com:80"));
        assertDoesNotThrow(() -> Authority.parse("example.com:001"));
        assertDoesNotThrow(() -> Authority.parse("%6A%6F%68%6E@example.com"));
        assertDoesNotThrow(() -> Authority.parse("101.102.103.104"));
        assertDoesNotThrow(() -> Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"));
        assertDoesNotThrow(() -> Authority.parse("[2001:db8:0:1:1:1:1:1]"));
        assertDoesNotThrow(() -> Authority.parse("[2001:0:9d38:6abd:0:0:0:42]"));
        assertDoesNotThrow(() -> Authority.parse("[fe80::1]"));
        assertDoesNotThrow(() -> Authority.parse("[2001:0:3238:DFE1:63::FEFB]"));
        assertDoesNotThrow(() -> Authority.parse("[v1.fe80::a+en1]"));
        assertDoesNotThrow(() -> Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D"));
        assertDoesNotThrow(() -> Authority.parse(""));
        assertDoesNotThrow(() -> Authority.parse(null));

        assertThrowsIAE(
            "The port value \"password@example.com\" has an invalid character \"p\" at the index 0.",
            () -> Authority.parse("user@name:password@example.com"));

        assertThrowsIAE(
            "The userinfo value \"müller\" has an invalid character \"ü\" at the index 1.",
            () -> Authority.parse("müller@example.com"));

        assertThrowsIAE(
            "The host value \"%XX\" has an invalid hex digit \"X\" at the index 1.",
            () -> Authority.parse("%XX"));
    }


    @Test
    public void test_getUserInfo()
    {
        assertEquals(null, Authority.parse("example.com").getUserinfo());
        assertEquals("john", Authority.parse("john@example.com:80").getUserinfo());
        assertEquals(null, Authority.parse("example.com:001").getUserinfo());
        assertEquals("%6A%6F%68%6E", Authority.parse("%6A%6F%68%6E@example.com").getUserinfo());
        assertEquals(null, Authority.parse("101.102.103.104").getUserinfo());
        assertEquals(null, Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getUserinfo());
        assertEquals(null, Authority.parse("[2001:db8:0:1:1:1:1:1]").getUserinfo());
        assertEquals(null, Authority.parse("[2001:0:9d38:6abd:0:0:0:42]").getUserinfo());
        assertEquals(null, Authority.parse("[fe80::1]").getUserinfo());
        assertEquals(null, Authority.parse("[2001:0:3238:DFE1:63::FEFB]").getUserinfo());
        assertEquals(null, Authority.parse("[v1.fe80::a+en1]").getUserinfo());
        assertEquals(null, Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").getUserinfo());
        assertEquals(null, Authority.parse("").getUserinfo());
    }


    @Test
    public void test_getHost()
    {
        assertEquals(new Host(REGNAME, "example.com"), Authority.parse("example.com").getHost());
        assertEquals(new Host(REGNAME, "example.com"), Authority.parse("john@example.com:80").getHost());
        assertEquals(new Host(REGNAME, "example.com"), Authority.parse("example.com:001").getHost());
        assertEquals(new Host(REGNAME, "example.com"), Authority.parse("%6A%6F%68%6E@example.com").getHost());
        assertEquals(new Host(IPV4, "101.102.103.104"), Authority.parse("101.102.103.104").getHost());
        assertEquals(new Host(IPV6, "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"), Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getHost());
        assertEquals(new Host(IPV6, "[2001:db8:0:1:1:1:1:1]"), Authority.parse("[2001:db8:0:1:1:1:1:1]").getHost());
        assertEquals(new Host(IPV6, "[2001:0:9d38:6abd:0:0:0:42]"), Authority.parse("[2001:0:9d38:6abd:0:0:0:42]").getHost());
        assertEquals(new Host(IPV6, "[fe80::1]"), Authority.parse("[fe80::1]").getHost());
        assertEquals(new Host(IPV6, "[2001:0:3238:DFE1:63::FEFB]"), Authority.parse("[2001:0:3238:DFE1:63::FEFB]").getHost());
        assertEquals(new Host(IPVFUTURE, "[v1.fe80::a+en1]"), Authority.parse("[v1.fe80::a+en1]").getHost());
        assertEquals(new Host(REGNAME, "%65%78%61%6D%70%6C%65%2E%63%6F%6D"), Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").getHost());
        assertEquals(new Host(REGNAME, ""), Authority.parse("").getHost());
    }


    @Test
    public void test_getPort()
    {
        assertEquals(-1, Authority.parse("example.com").getPort());
        assertEquals(80, Authority.parse("john@example.com:80").getPort());
        assertEquals(1, Authority.parse("example.com:001").getPort());
        assertEquals(-1, Authority.parse("%6A%6F%68%6E@example.com").getPort());
        assertEquals(-1, Authority.parse("101.102.103.104").getPort());
        assertEquals(-1, Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getPort());
        assertEquals(-1, Authority.parse("[2001:db8:0:1:1:1:1:1]").getPort());
        assertEquals(-1, Authority.parse("[2001:0:9d38:6abd:0:0:0:42]").getPort());
        assertEquals(-1, Authority.parse("[fe80::1]").getPort());
        assertEquals(-1, Authority.parse("[2001:0:3238:DFE1:63::FEFB]").getPort());
        assertEquals(-1, Authority.parse("[v1.fe80::a+en1]").getPort());
        assertEquals(-1, Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").getPort());
        assertEquals(-1, Authority.parse("").getPort());
    }


    @Test
    public void test_toString()
    {
        assertEquals("example.com", Authority.parse("example.com").toString());
        assertEquals("john@example.com:80", Authority.parse("john@example.com:80").toString());
        assertEquals("example.com:1", Authority.parse("example.com:001").toString());
        assertEquals("%6A%6F%68%6E@example.com", Authority.parse("%6A%6F%68%6E@example.com").toString());
        assertEquals("101.102.103.104", Authority.parse("101.102.103.104").toString());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").toString());
        assertEquals("[2001:db8:0:1:1:1:1:1]", Authority.parse("[2001:db8:0:1:1:1:1:1]").toString());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", Authority.parse("[2001:0:9d38:6abd:0:0:0:42]").toString());
        assertEquals("[fe80::1]", Authority.parse("[fe80::1]").toString());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", Authority.parse("[2001:0:3238:DFE1:63::FEFB]").toString());
        assertEquals("[v1.fe80::a+en1]", Authority.parse("[v1.fe80::a+en1]").toString());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D").toString());
        assertEquals("", Authority.parse("").toString());
    }


    @Test
    public void test_equals()
    {
        assertFalse(Authority.parse("FB").equals(Authority.parse("Ea")));
    }


    @Test
    public void test_compareTo()
    {
        assertEquals(0, Authority.parse("example.com").compareTo(Authority.parse("example.com")));

        assertTrue(Authority.parse("127.0.0.1").compareTo(Authority.parse("example.com")) < 0);

        assertThrowsNPE("A null value is not comparable.", () -> Authority.parse("example.com").compareTo(null));
    }
}
