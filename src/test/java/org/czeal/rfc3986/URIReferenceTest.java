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


import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import static org.czeal.rfc3986.TestUtils.assertThrowsISE;
import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import org.junit.jupiter.api.Test;


public class URIReferenceTest
{
    @Test
    public void test_parse()
    {
        URIReference uriRef1 = URIReference.parse("http://example.com");
        assertEquals("http://example.com", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals("http", uriRef1.getScheme());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("example.com", uriRef1.getAuthority().toString());
        assertEquals(null, uriRef1.getUserinfo());
        assertEquals("example.com", uriRef1.getHost().toString());
        assertEquals("example.com", uriRef1.getHost().getValue());
        assertEquals(REGNAME, uriRef1.getHost().getType());
        assertEquals(-1, uriRef1.getPort());
        assertEquals("", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReference.parse("hTTp://example.com");
        assertEquals("hTTp://example.com", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals("hTTp", uriRef2.getScheme());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("example.com", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("example.com", uriRef2.getHost().toString());
        assertEquals("example.com", uriRef2.getHost().getValue());
        assertEquals(REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals("", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = URIReference.parse("//example.com");
        assertEquals("//example.com", uriRef3.toString());
        assertEquals(true, uriRef3.isRelativeReference());
        assertEquals(null, uriRef3.getScheme());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals("example.com", uriRef3.getAuthority().toString());
        assertEquals(null, uriRef3.getUserinfo());
        assertEquals("example.com", uriRef3.getHost().toString());
        assertEquals("example.com", uriRef3.getHost().getValue());
        assertEquals(REGNAME, uriRef3.getHost().getType());
        assertEquals(-1, uriRef3.getPort());
        assertEquals("", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = URIReference.parse("http:");
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(false, uriRef4.hasAuthority());
        assertEquals(null, uriRef4.getAuthority());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals(null, uriRef4.getHost());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = URIReference.parse("http://john@example.com");
        assertEquals("http://john@example.com", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals("http", uriRef5.getScheme());
        assertEquals(true, uriRef5.hasAuthority());
        assertEquals("john@example.com", uriRef5.getAuthority().toString());
        assertEquals("john", uriRef5.getUserinfo());
        assertEquals("example.com", uriRef5.getHost().toString());
        assertEquals("example.com", uriRef5.getHost().getValue());
        assertEquals(REGNAME, uriRef5.getHost().getType());
        assertEquals(-1, uriRef5.getPort());
        assertEquals("", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = URIReference.parse("http://%6A%6F%68%6E@example.com");
        assertEquals("http://%6A%6F%68%6E@example.com", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals("http", uriRef6.getScheme());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("%6A%6F%68%6E@example.com", uriRef6.getAuthority().toString());
        assertEquals("%6A%6F%68%6E", uriRef6.getUserinfo());
        assertEquals("example.com", uriRef6.getHost().toString());
        assertEquals("example.com", uriRef6.getHost().getValue());
        assertEquals(REGNAME, uriRef6.getHost().getType());
        assertEquals(-1, uriRef6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = URIReference.parse("http://101.102.103.104");
        assertEquals("http://101.102.103.104", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals("http", uriRef7.getScheme());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("101.102.103.104", uriRef7.getAuthority().toString());
        assertEquals(null, uriRef7.getUserinfo());
        assertEquals("101.102.103.104", uriRef7.getHost().toString());
        assertEquals("101.102.103.104", uriRef7.getHost().getValue());
        assertEquals(HostType.IPV4, uriRef7.getHost().getType());
        assertEquals(-1, uriRef7.getPort());
        assertEquals("", uriRef7.getPath());
        assertEquals(null, uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]");
        assertEquals("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals("http", uriRef8.getScheme());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getAuthority().toString());
        assertEquals(null, uriRef8.getAuthority().getUserinfo());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getHost().toString());
        assertEquals("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]", uriRef8.getHost().getValue());
        assertEquals(IPV6, uriRef8.getHost().getType());
        assertEquals(-1, uriRef8.getPort());
        assertEquals("", uriRef8.getPath());
        assertEquals(null, uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = URIReference.parse("http://[2001:db8:0:1:1:1:1:1]");
        assertEquals("http://[2001:db8:0:1:1:1:1:1]", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals("http", uriRef9.getScheme());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getAuthority().toString());
        assertEquals(null, uriRef9.getUserinfo());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getHost().toString());
        assertEquals("[2001:db8:0:1:1:1:1:1]", uriRef9.getHost().getValue());
        assertEquals(IPV6, uriRef9.getHost().getType());
        assertEquals(-1, uriRef9.getPort());
        assertEquals("", uriRef9.getPath());
        assertEquals(null, uriRef9.getQuery());
        assertEquals(null, uriRef9.getFragment());

        URIReference uriRef10 = URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]");
        assertEquals("http://[2001:0:9d38:6abd:0:0:0:42]", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals("http", uriRef10.getScheme());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getAuthority().toString());
        assertEquals(null, uriRef10.getUserinfo());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getHost().toString());
        assertEquals("[2001:0:9d38:6abd:0:0:0:42]", uriRef10.getHost().getValue());
        assertEquals(IPV6, uriRef10.getHost().getType());
        assertEquals(-1, uriRef10.getPort());
        assertEquals("", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals(null, uriRef10.getFragment());

        URIReference uriRef11 = URIReference.parse("http://[fe80::1]");
        assertEquals("http://[fe80::1]", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals("http", uriRef11.getScheme());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("[fe80::1]", uriRef11.getAuthority().toString());
        assertEquals(null, uriRef11.getUserinfo());
        assertEquals("[fe80::1]", uriRef11.getHost().toString());
        assertEquals("[fe80::1]", uriRef11.getHost().getValue());
        assertEquals(IPV6, uriRef11.getHost().getType());
        assertEquals(-1, uriRef11.getPort());
        assertEquals("", uriRef11.getPath());
        assertEquals(null, uriRef11.getQuery());
        assertEquals(null, uriRef11.getFragment());

        URIReference uriRef12 = URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]");
        assertEquals("http://[2001:0:3238:DFE1:63::FEFB]", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals("http", uriRef12.getScheme());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getAuthority().toString());
        assertEquals(null, uriRef12.getUserinfo());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getHost().toString());
        assertEquals("[2001:0:3238:DFE1:63::FEFB]", uriRef12.getHost().getValue());
        assertEquals(IPV6, uriRef12.getHost().getType());
        assertEquals(-1, uriRef12.getPort());
        assertEquals("", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = URIReference.parse("http://[v1.fe80::a+en1]");
        assertEquals("http://[v1.fe80::a+en1]", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals("http", uriRef13.getScheme());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getAuthority().toString());
        assertEquals(null, uriRef13.getUserinfo());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getHost().toString());
        assertEquals("[v1.fe80::a+en1]", uriRef13.getHost().getValue());
        assertEquals(IPVFUTURE, uriRef13.getHost().getType());
        assertEquals(-1, uriRef13.getPort());
        assertEquals("", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D");
        assertEquals("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals("http", uriRef14.getScheme());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getAuthority().toString());
        assertEquals(null, uriRef14.getUserinfo());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getHost().toString());
        assertEquals("%65%78%61%6D%70%6C%65%2E%63%6F%6D", uriRef14.getHost().getValue());
        assertEquals(REGNAME, uriRef14.getHost().getType());
        assertEquals(-1, uriRef14.getPort());
        assertEquals("", uriRef14.getPath());
        assertEquals(null, uriRef14.getQuery());
        assertEquals(null, uriRef14.getFragment());

        URIReference uriRef15 = URIReference.parse("http://");
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals("http", uriRef15.getScheme());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("", uriRef15.getAuthority().toString());
        assertEquals(null, uriRef15.getUserinfo());
        assertEquals("", uriRef15.getHost().toString());
        assertEquals("", uriRef15.getHost().getValue());
        assertEquals(REGNAME, uriRef15.getHost().getType());
        assertEquals(-1, uriRef15.getPort());
        assertEquals("", uriRef15.getPath());
        assertEquals(null, uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = URIReference.parse("http:///a");
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals("http", uriRef16.getScheme());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("", uriRef16.getAuthority().toString());
        assertEquals(null, uriRef16.getUserinfo());
        assertEquals("", uriRef16.getHost().toString());
        assertEquals("", uriRef16.getHost().getValue());
        assertEquals(REGNAME, uriRef16.getHost().getType());
        assertEquals(-1, uriRef16.getPort());
        assertEquals("/a", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = URIReference.parse("http://example.com:80");
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals("http", uriRef17.getScheme());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("example.com:80", uriRef17.getAuthority().toString());
        assertEquals(null, uriRef17.getUserinfo());
        assertEquals("example.com", uriRef17.getHost().toString());
        assertEquals("example.com", uriRef17.getHost().getValue());
        assertEquals(REGNAME, uriRef17.getHost().getType());
        assertEquals(80, uriRef17.getPort());
        assertEquals("", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = URIReference.parse("http://example.com:");
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals("http", uriRef18.getScheme());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("example.com", uriRef18.getAuthority().toString());
        assertEquals(null, uriRef18.getUserinfo());
        assertEquals("example.com", uriRef18.getHost().toString());
        assertEquals("example.com", uriRef18.getHost().getValue());
        assertEquals(REGNAME, uriRef18.getHost().getType());
        assertEquals(-1, uriRef18.getPort());
        assertEquals("", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = URIReference.parse("http://example.com:001");
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals("http", uriRef19.getScheme());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("example.com:1", uriRef19.getAuthority().toString());
        assertEquals(null, uriRef19.getAuthority().getUserinfo());
        assertEquals("example.com", uriRef19.getHost().toString());
        assertEquals("example.com", uriRef19.getHost().getValue());
        assertEquals(REGNAME, uriRef19.getHost().getType());
        assertEquals(1, uriRef19.getPort());
        assertEquals("", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = URIReference.parse("http://example.com/a/b/c");
        assertEquals("http://example.com/a/b/c", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals("http", uriRef20.getScheme());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("example.com", uriRef20.getAuthority().toString());
        assertEquals(null, uriRef20.getAuthority().getUserinfo());
        assertEquals("example.com", uriRef20.getHost().toString());
        assertEquals("example.com", uriRef20.getHost().getValue());
        assertEquals(REGNAME, uriRef20.getHost().getType());
        assertEquals(-1, uriRef20.getPort());
        assertEquals("/a/b/c", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = URIReference.parse("http://example.com/%61/%62/%63");
        assertEquals("http://example.com/%61/%62/%63", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals("http", uriRef21.getScheme());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("example.com", uriRef21.getAuthority().toString());
        assertEquals(null, uriRef21.getUserinfo());
        assertEquals("example.com", uriRef21.getHost().toString());
        assertEquals("example.com", uriRef21.getHost().getValue());
        assertEquals(REGNAME, uriRef21.getHost().getType());
        assertEquals(-1, uriRef21.getPort());
        assertEquals("/%61/%62/%63", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = URIReference.parse("http:/a");
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(false, uriRef22.hasAuthority());
        assertEquals(null, uriRef22.getAuthority());
        assertEquals(null, uriRef22.getUserinfo());
        assertEquals(null, uriRef22.getHost());
        assertEquals(-1, uriRef22.getPort());
        assertEquals("/a", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = URIReference.parse("http:a");
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(false, uriRef23.hasAuthority());
        assertEquals(null, uriRef23.getAuthority());
        assertEquals(null, uriRef23.getUserinfo());
        assertEquals(null, uriRef23.getHost());
        assertEquals(-1, uriRef23.getPort());
        assertEquals("a", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = URIReference.parse("//");
        assertEquals(true, uriRef24.isRelativeReference());
        assertEquals(null, uriRef24.getScheme());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals("", uriRef24.getAuthority().toString());
        assertEquals(null, uriRef24.getUserinfo());
        assertEquals("", uriRef24.getHost().toString());
        assertEquals("", uriRef24.getHost().getValue());
        assertEquals(REGNAME, uriRef24.getHost().getType());
        assertEquals(-1, uriRef24.getPort());
        assertEquals("", uriRef24.getPath());
        assertEquals(null, uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        URIReference uriRef25 = URIReference.parse("http://example.com?q");
        assertEquals(false, uriRef25.isRelativeReference());
        assertEquals("http", uriRef25.getScheme());
        assertEquals(true, uriRef25.hasAuthority());
        assertEquals("example.com", uriRef25.getAuthority().toString());
        assertEquals(null, uriRef25.getUserinfo());
        assertEquals("example.com", uriRef25.getHost().toString());
        assertEquals("example.com", uriRef25.getHost().getValue());
        assertEquals(REGNAME, uriRef25.getHost().getType());
        assertEquals(-1, uriRef25.getPort());
        assertEquals("", uriRef25.getPath());
        assertEquals("q", uriRef25.getQuery());
        assertEquals(null, uriRef25.getFragment());

        URIReference uriRef26 = URIReference.parse("http://example.com?");
        assertEquals(false, uriRef26.isRelativeReference());
        assertEquals("http", uriRef26.getScheme());
        assertEquals(true, uriRef26.hasAuthority());
        assertEquals("example.com", uriRef26.getAuthority().toString());
        assertEquals(null, uriRef26.getUserinfo());
        assertEquals("example.com", uriRef26.getHost().toString());
        assertEquals("example.com", uriRef26.getHost().getValue());
        assertEquals(REGNAME, uriRef26.getHost().getType());
        assertEquals(-1, uriRef26.getPort());
        assertEquals("", uriRef26.getPath());
        assertEquals("", uriRef26.getQuery());
        assertEquals(null, uriRef26.getFragment());

        URIReference uriRef27 = URIReference.parse("http://example.com#f");
        assertEquals(false, uriRef27.isRelativeReference());
        assertEquals("http", uriRef27.getScheme());
        assertEquals(true, uriRef27.hasAuthority());
        assertEquals("example.com", uriRef27.getAuthority().toString());
        assertEquals(null, uriRef27.getUserinfo());
        assertEquals("example.com", uriRef27.getHost().toString());
        assertEquals("example.com", uriRef27.getHost().getValue());
        assertEquals(REGNAME, uriRef27.getHost().getType());
        assertEquals(-1, uriRef27.getPort());
        assertEquals("", uriRef27.getPath());
        assertEquals(null, uriRef27.getQuery());
        assertEquals("f", uriRef27.getFragment());

        URIReference uriRef28 = URIReference.parse("http://example.com#");
        assertEquals(false, uriRef28.isRelativeReference());
        assertEquals("http", uriRef28.getScheme());
        assertEquals(true, uriRef28.hasAuthority());
        assertEquals("example.com", uriRef28.getAuthority().toString());
        assertEquals(null, uriRef28.getUserinfo());
        assertEquals("example.com", uriRef28.getHost().toString());
        assertEquals("example.com", uriRef28.getHost().getValue());
        assertEquals(REGNAME, uriRef28.getHost().getType());
        assertEquals(-1, uriRef28.getPort());
        assertEquals("", uriRef28.getPath());
        assertEquals(null, uriRef28.getQuery());
        assertEquals("", uriRef28.getFragment());

        URIReference uriRef29 = URIReference.parse("");
        assertEquals(true, uriRef29.isRelativeReference());
        assertEquals(null, uriRef29.getScheme());
        assertEquals(false, uriRef29.hasAuthority());
        assertEquals(null, uriRef29.getAuthority());
        assertEquals(null, uriRef29.getUserinfo());
        assertEquals(null, uriRef29.getHost());
        assertEquals(-1, uriRef29.getPort());
        assertEquals("", uriRef29.getPath());
        assertEquals(null, uriRef29.getQuery());
        assertEquals(null, uriRef29.getFragment());

        assertThrowsIAE(
            "The path segment value \"1invalid:\" has an invalid character \":\" at the index 8.",
            () -> URIReference.parse("1invalid://example.com"));

        assertThrowsIAE(
            "The host value \"v@w\" has an invalid character \"@\" at the index 1.",
            () -> URIReference.parse("http://u@v@w"));

        assertThrowsIAE(
            "The port value \"1:2:3\" has an invalid character \":\" at the index 1.",
            () -> URIReference.parse("http://example.com:1:2:3"));

        assertThrowsIAE(
            "The query value \"[invalid_query]\" has an invalid character \"[\" at the index 0.",
            () -> URIReference.parse("http://example.com?[invalid_query]"));

        assertThrowsIAE(
            "The fragment value \"[invalid_fragment]\" has an invalid character \"[\" at the index 0.",
            () -> URIReference.parse("http://example.com#[invalid_fragment]"));

        assertThrowsIAE(
            "The port value \"b\" has an invalid character \"b\" at the index 0.",
            () -> URIReference.parse("//a:b"));

        assertThrowsIAE(
            "The port value \":\" has an invalid character \":\" at the index 0.",
            () -> URIReference.parse("//::"));
    }


    @Test
    public void test_isRelativeReference()
    {
        assertEquals(false, URIReference.parse("http://example.com").isRelativeReference());
        assertEquals(false, URIReference.parse("hTTp://example.com").isRelativeReference());
        assertEquals(true, URIReference.parse("//example.com").isRelativeReference());
        assertEquals(false, URIReference.parse("http:").isRelativeReference());
        assertEquals(false, URIReference.parse("http://john@example.com").isRelativeReference());
        assertEquals(false, URIReference.parse("http://%6A%6F%68%6E@example.com").isRelativeReference());
        assertEquals(false, URIReference.parse("http://101.102.103.104").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[fe80::1]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://[v1.fe80::a+en1]").isRelativeReference());
        assertEquals(false, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").isRelativeReference());
        assertEquals(false, URIReference.parse("http://").isRelativeReference());
        assertEquals(false, URIReference.parse("http:///a").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com:80").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com:").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com:001").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com/a/b/c").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com/%61/%62/%63").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com?q").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com?").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com#f").isRelativeReference());
        assertEquals(false, URIReference.parse("http://example.com#").isRelativeReference());
        assertEquals(false, URIReference.parse("http:/a").isRelativeReference());
        assertEquals(false, URIReference.parse("http:a").isRelativeReference());
        assertEquals(true, URIReference.parse("//").isRelativeReference());
        assertEquals(true, URIReference.parse("").isRelativeReference());
    }


    @Test
    public void test_getScheme()
    {
        assertEquals("http", URIReference.parse("http://example.com").getScheme());
        assertEquals("hTTp", URIReference.parse("hTTp://example.com").getScheme());
        assertEquals(null, URIReference.parse("//example.com").getScheme());
        assertEquals("http", URIReference.parse("http:").getScheme());
        assertEquals("http", URIReference.parse("http://john@example.com").getScheme());
        assertEquals("http", URIReference.parse("http://%6A%6F%68%6E@example.com").getScheme());
        assertEquals("http", URIReference.parse("http://101.102.103.104").getScheme());
        assertEquals("http", URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getScheme());
        assertEquals("http", URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getScheme());
        assertEquals("http", URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getScheme());
        assertEquals("http", URIReference.parse("http://[fe80::1]").getScheme());
        assertEquals("http", URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getScheme());
        assertEquals("http", URIReference.parse("http://[v1.fe80::a+en1]").getScheme());
        assertEquals("http", URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getScheme());
        assertEquals("http", URIReference.parse("http://").getScheme());
        assertEquals("http", URIReference.parse("http:///a").getScheme());
        assertEquals("http", URIReference.parse("http://example.com:80").getScheme());
        assertEquals("http", URIReference.parse("http://example.com:").getScheme());
        assertEquals("http", URIReference.parse("http://example.com:001").getScheme());
        assertEquals("http", URIReference.parse("http://example.com/a/b/c").getScheme());
        assertEquals("http", URIReference.parse("http://example.com/%61/%62/%63").getScheme());
        assertEquals("http", URIReference.parse("http://example.com?q").getScheme());
        assertEquals("http", URIReference.parse("http://example.com?").getScheme());
        assertEquals("http", URIReference.parse("http://example.com#f").getScheme());
        assertEquals("http", URIReference.parse("http://example.com#").getScheme());
        assertEquals("http", URIReference.parse("http:/a").getScheme());
        assertEquals("http", URIReference.parse("http:a").getScheme());
        assertEquals(null, URIReference.parse("//").getScheme());
        assertEquals(null, URIReference.parse("").getScheme());
    }


    @Test
    public void test_hasAuthority()
    {
        assertEquals(true, URIReference.parse("http://example.com").hasAuthority());
        assertEquals(true, URIReference.parse("hTTp://example.com").hasAuthority());
        assertEquals(true, URIReference.parse("//example.com").hasAuthority());
        assertEquals(false, URIReference.parse("http:").hasAuthority());
        assertEquals(true, URIReference.parse("http://john@example.com").hasAuthority());
        assertEquals(true, URIReference.parse("http://%6A%6F%68%6E@example.com").hasAuthority());
        assertEquals(true, URIReference.parse("http://101.102.103.104").hasAuthority());
        assertEquals(true, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").hasAuthority());
        assertEquals(true, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").hasAuthority());
        assertEquals(true, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").hasAuthority());
        assertEquals(true, URIReference.parse("http://[fe80::1]").hasAuthority());
        assertEquals(true, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").hasAuthority());
        assertEquals(true, URIReference.parse("http://[v1.fe80::a+en1]").hasAuthority());
        assertEquals(true, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").hasAuthority());
        assertEquals(true, URIReference.parse("http://").hasAuthority());
        assertEquals(true, URIReference.parse("http:///a").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com:80").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com:").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com:001").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com/a/b/c").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com/%61/%62/%63").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com?q").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com?").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com#f").hasAuthority());
        assertEquals(true, URIReference.parse("http://example.com#").hasAuthority());
        assertEquals(false, URIReference.parse("http:/a").hasAuthority());
        assertEquals(false, URIReference.parse("http:a").hasAuthority());
        assertEquals(true, URIReference.parse("//").hasAuthority());
        assertEquals(false, URIReference.parse("").hasAuthority());
    }


    @Test
    public void test_getAuthority()
    {
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("hTTp://example.com").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("//example.com").getAuthority());
        assertEquals(null, URIReference.parse("http:").getAuthority());
        assertEquals(Authority.parse("john@example.com"), URIReference.parse("http://john@example.com").getAuthority());
        assertEquals(Authority.parse("%6A%6F%68%6E@example.com"), URIReference.parse("http://%6A%6F%68%6E@example.com").getAuthority());
        assertEquals(Authority.parse("101.102.103.104"), URIReference.parse("http://101.102.103.104").getAuthority());
        assertEquals(Authority.parse("[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"), URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getAuthority());
        assertEquals(Authority.parse("[2001:db8:0:1:1:1:1:1]"), URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getAuthority());
        assertEquals(Authority.parse("[2001:0:9d38:6abd:0:0:0:42]"), URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getAuthority());
        assertEquals(Authority.parse("[fe80::1]"), URIReference.parse("http://[fe80::1]").getAuthority());
        assertEquals(Authority.parse("[2001:0:3238:DFE1:63::FEFB]"), URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getAuthority());
        assertEquals(Authority.parse("[v1.fe80::a+en1]"), URIReference.parse("http://[v1.fe80::a+en1]").getAuthority());
        assertEquals(Authority.parse("%65%78%61%6D%70%6C%65%2E%63%6F%6D"), URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getAuthority());
        assertEquals(Authority.parse(""), URIReference.parse("http://").getAuthority());
        assertEquals(Authority.parse(""), URIReference.parse("http:///a").getAuthority());
        assertEquals(Authority.parse("example.com:80"), URIReference.parse("http://example.com:80").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com:").getAuthority());
        assertEquals(Authority.parse("example.com:001"), URIReference.parse("http://example.com:001").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com/a/b/c").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com/%61/%62/%63").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com?q").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com?").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com#f").getAuthority());
        assertEquals(Authority.parse("example.com"), URIReference.parse("http://example.com#").getAuthority());
        assertEquals(null, URIReference.parse("http:/a").getAuthority());
        assertEquals(null, URIReference.parse("http:a").getAuthority());
        assertEquals(Authority.parse(""), URIReference.parse("//").getAuthority());
        assertEquals(null, URIReference.parse("").getAuthority());
    }


    @Test
    public void test_getUserInfo()
    {
        assertEquals(null, URIReference.parse("http://example.com").getUserinfo());
        assertEquals(null, URIReference.parse("hTTp://example.com").getUserinfo());
        assertEquals(null, URIReference.parse("//example.com").getUserinfo());
        assertEquals(null, URIReference.parse("http:").getUserinfo());
        assertEquals("john", URIReference.parse("http://john@example.com").getUserinfo());
        assertEquals("%6A%6F%68%6E", URIReference.parse("http://%6A%6F%68%6E@example.com").getUserinfo());
        assertEquals(null, URIReference.parse("http://101.102.103.104").getUserinfo());
        assertEquals(null, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getUserinfo());
        assertEquals(null, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getUserinfo());
        assertEquals(null, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getUserinfo());
        assertEquals(null, URIReference.parse("http://[fe80::1]").getUserinfo());
        assertEquals(null, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getUserinfo());
        assertEquals(null, URIReference.parse("http://[v1.fe80::a+en1]").getUserinfo());
        assertEquals(null, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getUserinfo());
        assertEquals(null, URIReference.parse("http://").getUserinfo());
        assertEquals(null, URIReference.parse("http:///a").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com:80").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com:").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com:001").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com/a/b/c").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com/%61/%62/%63").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com?q").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com?").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com#f").getUserinfo());
        assertEquals(null, URIReference.parse("http://example.com#").getUserinfo());
        assertEquals(null, URIReference.parse("http:/a").getUserinfo());
        assertEquals(null, URIReference.parse("http:a").getUserinfo());
        assertEquals(null, URIReference.parse("//").getUserinfo());
        assertEquals(null, URIReference.parse("").getUserinfo());
    }


    @Test
    public void testHost()
    {
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("hTTp://example.com").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("//example.com").getHost());
        assertEquals(null, URIReference.parse("http:").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://john@example.com").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://%6A%6F%68%6E@example.com").getHost());
        assertEquals(new Host(IPV4, "101.102.103.104"), URIReference.parse("http://101.102.103.104").getHost());
        assertEquals(new Host(IPV6, "[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]"), URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getHost());
        assertEquals(new Host(IPV6, "[2001:db8:0:1:1:1:1:1]"), URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getHost());
        assertEquals(new Host(IPV6, "[2001:0:9d38:6abd:0:0:0:42]"), URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getHost());
        assertEquals(new Host(IPV6, "[fe80::1]"), URIReference.parse("http://[fe80::1]").getHost());
        assertEquals(new Host(IPV6, "[2001:0:3238:DFE1:63::FEFB]"), URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getHost());
        assertEquals(new Host(IPVFUTURE, "[v1.fe80::a+en1]"), URIReference.parse("http://[v1.fe80::a+en1]").getHost());
        assertEquals(new Host(REGNAME, "%65%78%61%6D%70%6C%65%2E%63%6F%6D"), URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getHost());
        assertEquals(new Host(REGNAME, ""), URIReference.parse("http://").getHost());
        assertEquals(new Host(REGNAME, ""), URIReference.parse("http:///a").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com:80").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com:").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com:001").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com/a/b/c").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com/%61/%62/%63").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com?q").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com?").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com#f").getHost());
        assertEquals(new Host(REGNAME, "example.com"), URIReference.parse("http://example.com#").getHost());
        assertEquals(null, URIReference.parse("http:/a").getHost());
        assertEquals(null, URIReference.parse("http:a").getHost());
        assertEquals(new Host(REGNAME, ""), URIReference.parse("//").getHost());
        assertEquals(null, URIReference.parse("").getHost());
    }


    @Test
    public void test_getPort()
    {
        assertEquals(-1, URIReference.parse("http://example.com").getPort());
        assertEquals(-1, URIReference.parse("hTTp://example.com").getPort());
        assertEquals(-1, URIReference.parse("//example.com").getPort());
        assertEquals(-1, URIReference.parse("http:").getPort());
        assertEquals(-1, URIReference.parse("http://john@example.com").getPort());
        assertEquals(-1, URIReference.parse("http://%6A%6F%68%6E@example.com").getPort());
        assertEquals(-1, URIReference.parse("http://101.102.103.104").getPort());
        assertEquals(-1, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getPort());
        assertEquals(-1, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getPort());
        assertEquals(-1, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getPort());
        assertEquals(-1, URIReference.parse("http://[fe80::1]").getPort());
        assertEquals(-1, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getPort());
        assertEquals(-1, URIReference.parse("http://[v1.fe80::a+en1]").getPort());
        assertEquals(-1, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getPort());
        assertEquals(-1, URIReference.parse("http://").getPort());
        assertEquals(-1, URIReference.parse("http:///a").getPort());
        assertEquals(80, URIReference.parse("http://example.com:80").getPort());
        assertEquals(-1, URIReference.parse("http://example.com:").getPort());
        assertEquals(1, URIReference.parse("http://example.com:001").getPort());
        assertEquals(-1, URIReference.parse("http://example.com/a/b/c").getPort());
        assertEquals(-1, URIReference.parse("http://example.com/%61/%62/%63").getPort());
        assertEquals(-1, URIReference.parse("http://example.com?q").getPort());
        assertEquals(-1, URIReference.parse("http://example.com?").getPort());
        assertEquals(-1, URIReference.parse("http://example.com#f").getPort());
        assertEquals(-1, URIReference.parse("http://example.com#").getPort());
        assertEquals(-1, URIReference.parse("http:/a").getPort());
        assertEquals(-1, URIReference.parse("http:a").getPort());
        assertEquals(-1, URIReference.parse("//").getPort());
        assertEquals(-1, URIReference.parse("").getPort());
    }


    @Test
    public void test_getPath()
    {
        assertEquals("", URIReference.parse("http://example.com").getPath());
        assertEquals("", URIReference.parse("hTTp://example.com").getPath());
        assertEquals("", URIReference.parse("//example.com").getPath());
        assertEquals("", URIReference.parse("http:").getPath());
        assertEquals("", URIReference.parse("http://john@example.com").getPath());
        assertEquals("", URIReference.parse("http://%6A%6F%68%6E@example.com").getPath());
        assertEquals("", URIReference.parse("http://101.102.103.104").getPath());
        assertEquals("", URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getPath());
        assertEquals("", URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getPath());
        assertEquals("", URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getPath());
        assertEquals("", URIReference.parse("http://[fe80::1]").getPath());
        assertEquals("", URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getPath());
        assertEquals("", URIReference.parse("http://[v1.fe80::a+en1]").getPath());
        assertEquals("", URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getPath());
        assertEquals("", URIReference.parse("http://").getPath());
        assertEquals("/a", URIReference.parse("http:///a").getPath());
        assertEquals("", URIReference.parse("http://example.com:80").getPath());
        assertEquals("", URIReference.parse("http://example.com:").getPath());
        assertEquals("", URIReference.parse("http://example.com:001").getPath());
        assertEquals("/a/b/c", URIReference.parse("http://example.com/a/b/c").getPath());
        assertEquals("/%61/%62/%63", URIReference.parse("http://example.com/%61/%62/%63").getPath());
        assertEquals("", URIReference.parse("http://example.com?q").getPath());
        assertEquals("", URIReference.parse("http://example.com?").getPath());
        assertEquals("", URIReference.parse("http://example.com#f").getPath());
        assertEquals("", URIReference.parse("http://example.com#").getPath());
        assertEquals("/a", URIReference.parse("http:/a").getPath());
        assertEquals("a", URIReference.parse("http:a").getPath());
        assertEquals("", URIReference.parse("//").getPath());
        assertEquals("", URIReference.parse("").getPath());
    }


    @Test
    public void test_getQuery()
    {
        assertEquals(null, URIReference.parse("http://example.com").getQuery());
        assertEquals(null, URIReference.parse("hTTp://example.com").getQuery());
        assertEquals(null, URIReference.parse("//example.com").getQuery());
        assertEquals(null, URIReference.parse("http:").getQuery());
        assertEquals(null, URIReference.parse("http://john@example.com").getQuery());
        assertEquals(null, URIReference.parse("http://%6A%6F%68%6E@example.com").getQuery());
        assertEquals(null, URIReference.parse("http://101.102.103.104").getQuery());
        assertEquals(null, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getQuery());
        assertEquals(null, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getQuery());
        assertEquals(null, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getQuery());
        assertEquals(null, URIReference.parse("http://[fe80::1]").getQuery());
        assertEquals(null, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getQuery());
        assertEquals(null, URIReference.parse("http://[v1.fe80::a+en1]").getQuery());
        assertEquals(null, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getQuery());
        assertEquals(null, URIReference.parse("http://").getQuery());
        assertEquals(null, URIReference.parse("http:///a").getQuery());
        assertEquals(null, URIReference.parse("http://example.com:80").getQuery());
        assertEquals(null, URIReference.parse("http://example.com:").getQuery());
        assertEquals(null, URIReference.parse("http://example.com:001").getQuery());
        assertEquals(null, URIReference.parse("http://example.com/a/b/c").getQuery());
        assertEquals(null, URIReference.parse("http://example.com/%61/%62/%63").getQuery());
        assertEquals("q", URIReference.parse("http://example.com?q").getQuery());
        assertEquals("", URIReference.parse("http://example.com?").getQuery());
        assertEquals(null, URIReference.parse("http://example.com#f").getQuery());
        assertEquals(null, URIReference.parse("http://example.com#").getQuery());
        assertEquals(null, URIReference.parse("http:/a").getQuery());
        assertEquals(null, URIReference.parse("http:a").getQuery());
        assertEquals(null, URIReference.parse("//").getQuery());
        assertEquals(null, URIReference.parse("").getQuery());
    }


    @Test
    public void test_getFragment()
    {
        assertEquals(null, URIReference.parse("http://example.com").getFragment());
        assertEquals(null, URIReference.parse("hTTp://example.com").getFragment());
        assertEquals(null, URIReference.parse("//example.com").getFragment());
        assertEquals(null, URIReference.parse("http:").getFragment());
        assertEquals(null, URIReference.parse("http://john@example.com").getFragment());
        assertEquals(null, URIReference.parse("http://%6A%6F%68%6E@example.com").getFragment());
        assertEquals(null, URIReference.parse("http://101.102.103.104").getFragment());
        assertEquals(null, URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").getFragment());
        assertEquals(null, URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").getFragment());
        assertEquals(null, URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").getFragment());
        assertEquals(null, URIReference.parse("http://[fe80::1]").getFragment());
        assertEquals(null, URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").getFragment());
        assertEquals(null, URIReference.parse("http://[v1.fe80::a+en1]").getFragment());
        assertEquals(null, URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").getFragment());
        assertEquals(null, URIReference.parse("http://").getFragment());
        assertEquals(null, URIReference.parse("http:///a").getFragment());
        assertEquals(null, URIReference.parse("http://example.com:80").getFragment());
        assertEquals(null, URIReference.parse("http://example.com:").getFragment());
        assertEquals(null, URIReference.parse("http://example.com:001").getFragment());
        assertEquals(null, URIReference.parse("http://example.com/a/b/c").getFragment());
        assertEquals(null, URIReference.parse("http://example.com/%61/%62/%63").getFragment());
        assertEquals(null, URIReference.parse("http://example.com?q").getFragment());
        assertEquals(null, URIReference.parse("http://example.com?").getFragment());
        assertEquals("f", URIReference.parse("http://example.com#f").getFragment());
        assertEquals("", URIReference.parse("http://example.com#").getFragment());
        assertEquals(null, URIReference.parse("http:/a").getFragment());
        assertEquals(null, URIReference.parse("http:a").getFragment());
        assertEquals(null, URIReference.parse("//").getFragment());
        assertEquals(null, URIReference.parse("").getFragment());
    }


    @Test
    public void test_equals()
    {
        assertTrue(URIReference.parse("http://example.com").equals(URIReference.parse("http://example.com")));
        assertTrue(URIReference.parse("hTTp://example.com").equals(URIReference.parse("hTTp://example.com")));
        assertTrue(URIReference.parse("//example.com").equals(URIReference.parse("//example.com")));
        assertTrue(URIReference.parse("http:").equals(URIReference.parse("http:")));
        assertTrue(URIReference.parse("http://john@example.com").equals(URIReference.parse("http://john@example.com")));
        assertTrue(URIReference.parse("http://%6A%6F%68%6E@example.com").equals(URIReference.parse("http://%6A%6F%68%6E@example.com")));
        assertTrue(URIReference.parse("http://101.102.103.104").equals(URIReference.parse("http://101.102.103.104")));
        assertTrue(URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]").equals(URIReference.parse("http://[2001:0db8:0001:0000:0000:0ab9:C0A8:0102]")));
        assertTrue(URIReference.parse("http://[2001:db8:0:1:1:1:1:1]").equals(URIReference.parse("http://[2001:db8:0:1:1:1:1:1]")));
        assertTrue(URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]").equals(URIReference.parse("http://[2001:0:9d38:6abd:0:0:0:42]")));
        assertTrue(URIReference.parse("http://[fe80::1]").equals(URIReference.parse("http://[fe80::1]")));
        assertTrue(URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]").equals(URIReference.parse("http://[2001:0:3238:DFE1:63::FEFB]")));
        assertTrue(URIReference.parse("http://[v1.fe80::a+en1]").equals(URIReference.parse("http://[v1.fe80::a+en1]")));
        assertTrue(URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D").equals(URIReference.parse("http://%65%78%61%6D%70%6C%65%2E%63%6F%6D")));
        assertTrue(URIReference.parse("http://").equals(URIReference.parse("http://")));
        assertTrue(URIReference.parse("http:///a").equals(URIReference.parse("http:///a")));
        assertTrue(URIReference.parse("http://example.com:80").equals(URIReference.parse("http://example.com:80")));
        assertTrue(URIReference.parse("http://example.com:").equals(URIReference.parse("http://example.com:")));
        assertTrue(URIReference.parse("http://example.com:001").equals(URIReference.parse("http://example.com:001")));
        assertTrue(URIReference.parse("http://example.com/a/b/c").equals(URIReference.parse("http://example.com/a/b/c")));
        assertTrue(URIReference.parse("http://example.com/%61/%62/%63").equals(URIReference.parse("http://example.com/%61/%62/%63")));
        assertTrue(URIReference.parse("http://example.com?q").equals(URIReference.parse("http://example.com?q")));
        assertTrue(URIReference.parse("http://example.com?").equals(URIReference.parse("http://example.com?")));
        assertTrue(URIReference.parse("http://example.com#f").equals(URIReference.parse("http://example.com#f")));
        assertTrue(URIReference.parse("http://example.com#").equals(URIReference.parse("http://example.com#")));
        assertTrue(URIReference.parse("http:/a").equals(URIReference.parse("http:/a")));
        assertTrue(URIReference.parse("http:a").equals(URIReference.parse("http:a")));
        assertTrue(URIReference.parse("//").equals(URIReference.parse("//")));
        assertTrue(URIReference.parse("").equals(URIReference.parse("")));
        assertFalse(URIReference.parse("http://example.com/1ot").equals(URIReference.parse("http://example.com/1pU")));
    }


    @Test
    public void test_resolve()
    {
        URIReference uriRef1 = URIReference.parse("http://a/b/c/d;p?q").resolve("g:h");
        assertEquals("g:h", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals("g", uriRef1.getScheme());
        assertEquals(false, uriRef1.hasAuthority());
        assertEquals(null, uriRef1.getAuthority());
        assertEquals(null, uriRef1.getUserinfo());
        assertEquals(null, uriRef1.getHost());
        assertEquals(-1, uriRef1.getPort());
        assertEquals("h", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReference.parse("http://a/b/c/d;p?q").resolve("g");
        assertEquals("http://a/b/c/g", uriRef2.toString());
        assertEquals(false, uriRef2.isRelativeReference());
        assertEquals("http", uriRef2.getScheme());
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("a", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("a", uriRef2.getHost().toString());
        assertEquals("a", uriRef2.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals("/b/c/g", uriRef2.getPath());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = URIReference.parse("http://a/b/c/d;p?q").resolve("./g");
        assertEquals("http://a/b/c/g", uriRef3.toString());
        assertEquals(false, uriRef3.isRelativeReference());
        assertEquals("http", uriRef3.getScheme());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals("a", uriRef3.getAuthority().toString());
        assertEquals(null, uriRef3.getUserinfo());
        assertEquals("a", uriRef3.getHost().toString());
        assertEquals("a", uriRef3.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef3.getHost().getType());
        assertEquals(-1, uriRef3.getPort());
        assertEquals("/b/c/g", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = URIReference.parse("http://a/b/c/d;p?q").resolve("g/");
        assertEquals("http://a/b/c/g/", uriRef4.toString());
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(true, uriRef4.hasAuthority());
        assertEquals("a", uriRef4.getAuthority().toString());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals("a", uriRef4.getHost().toString());
        assertEquals("a", uriRef4.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef4.getHost().getType());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("/b/c/g/", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = URIReference.parse("http://a/b/c/d;p?q").resolve("/g");
        assertEquals("http://a/g", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals("http", uriRef5.getScheme());
        assertEquals(true, uriRef4.hasAuthority());
        assertEquals("a", uriRef4.getAuthority().toString());
        assertEquals(null, uriRef4.getUserinfo());
        assertEquals("a", uriRef4.getHost().toString());
        assertEquals("a", uriRef4.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef4.getHost().getType());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("/g", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = URIReference.parse("http://a/b/c/d;p?q").resolve("//g");
        assertEquals("http://g", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals("http", uriRef6.getScheme());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("g", uriRef6.getAuthority().toString());
        assertEquals(null, uriRef6.getUserinfo());
        assertEquals("g", uriRef6.getHost().toString());
        assertEquals("g", uriRef6.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef6.getHost().getType());
        assertEquals(-1, uriRef6.getPort());
        assertEquals("", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = URIReference.parse("http://a/b/c/d;p?q").resolve("?y");
        assertEquals("http://a/b/c/d;p?y", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals("http", uriRef7.getScheme());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("a", uriRef7.getAuthority().toString());
        assertEquals(null, uriRef7.getUserinfo());
        assertEquals("a", uriRef7.getHost().toString());
        assertEquals("a", uriRef7.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef7.getHost().getType());
        assertEquals(-1, uriRef7.getPort());
        assertEquals("/b/c/d;p", uriRef7.getPath());
        assertEquals("y", uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = URIReference.parse("http://a/b/c/d;p?q").resolve("g?y");
        assertEquals("http://a/b/c/g?y", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals("http", uriRef8.getScheme());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("a", uriRef8.getAuthority().toString());
        assertEquals(null, uriRef8.getUserinfo());
        assertEquals("a", uriRef8.getHost().toString());
        assertEquals("a", uriRef8.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef8.getHost().getType());
        assertEquals(-1, uriRef8.getPort());
        assertEquals("/b/c/g", uriRef8.getPath());
        assertEquals("y", uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = URIReference.parse("http://a/b/c/d;p?q").resolve("#s");
        assertEquals("http://a/b/c/d;p?q#s", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals("http", uriRef9.getScheme());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("a", uriRef9.getAuthority().toString());
        assertEquals(null, uriRef9.getUserinfo());
        assertEquals("a", uriRef9.getHost().toString());
        assertEquals("a", uriRef9.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef9.getHost().getType());
        assertEquals(-1, uriRef9.getPort());
        assertEquals("/b/c/d;p", uriRef9.getPath());
        assertEquals("q", uriRef9.getQuery());
        assertEquals("s", uriRef9.getFragment());

        URIReference uriRef10 = URIReference.parse("http://a/b/c/d;p?q").resolve("g#s");
        assertEquals("http://a/b/c/g#s", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals("http", uriRef10.getScheme());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("a", uriRef10.getAuthority().toString());
        assertEquals(null, uriRef10.getUserinfo());
        assertEquals("a", uriRef10.getHost().toString());
        assertEquals("a", uriRef10.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef10.getHost().getType());
        assertEquals(-1, uriRef10.getPort());
        assertEquals("/b/c/g", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals("s", uriRef10.getFragment());

        URIReference uriRef11 = URIReference.parse("http://a/b/c/d;p?q").resolve("g?y#s");
        assertEquals("http://a/b/c/g?y#s", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals("http", uriRef11.getScheme());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("a", uriRef11.getAuthority().toString());
        assertEquals(null, uriRef11.getUserinfo());
        assertEquals("a", uriRef11.getHost().toString());
        assertEquals("a", uriRef11.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef11.getHost().getType());
        assertEquals(-1, uriRef11.getPort());
        assertEquals("/b/c/g", uriRef11.getPath());
        assertEquals("y", uriRef11.getQuery());
        assertEquals("s", uriRef11.getFragment());

        URIReference uriRef12 = URIReference.parse("http://a/b/c/d;p?q").resolve(";x");
        assertEquals("http://a/b/c/;x", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals("http", uriRef12.getScheme());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("a", uriRef12.getAuthority().toString());
        assertEquals(null, uriRef12.getUserinfo());
        assertEquals("a", uriRef12.getHost().toString());
        assertEquals("a", uriRef12.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef12.getHost().getType());
        assertEquals(-1, uriRef12.getPort());
        assertEquals("/b/c/;x", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        URIReference uriRef13 = URIReference.parse("http://a/b/c/d;p?q").resolve("g;x");
        assertEquals("http://a/b/c/g;x", uriRef13.toString());
        assertEquals(false, uriRef13.isRelativeReference());
        assertEquals("http", uriRef13.getScheme());
        assertEquals(true, uriRef13.hasAuthority());
        assertEquals("a", uriRef13.getAuthority().toString());
        assertEquals(null, uriRef13.getUserinfo());
        assertEquals("a", uriRef13.getHost().toString());
        assertEquals("a", uriRef13.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef13.getHost().getType());
        assertEquals(-1, uriRef13.getPort());
        assertEquals("/b/c/g;x", uriRef13.getPath());
        assertEquals(null, uriRef13.getQuery());
        assertEquals(null, uriRef13.getFragment());

        URIReference uriRef14 = URIReference.parse("http://a/b/c/d;p?q").resolve("g;x?y#s");
        assertEquals("http://a/b/c/g;x?y#s", uriRef14.toString());
        assertEquals(false, uriRef14.isRelativeReference());
        assertEquals("http", uriRef14.getScheme());
        assertEquals(true, uriRef14.hasAuthority());
        assertEquals("a", uriRef14.getAuthority().toString());
        assertEquals(null, uriRef14.getUserinfo());
        assertEquals("a", uriRef14.getHost().toString());
        assertEquals("a", uriRef14.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef14.getHost().getType());
        assertEquals(-1, uriRef14.getPort());
        assertEquals("/b/c/g;x", uriRef14.getPath());
        assertEquals("y", uriRef14.getQuery());
        assertEquals("s", uriRef14.getFragment());

        URIReference uriRef15 = URIReference.parse("http://a/b/c/d;p?q").resolve("");
        assertEquals("http://a/b/c/d;p?q", uriRef15.toString());
        assertEquals(false, uriRef15.isRelativeReference());
        assertEquals("http", uriRef15.getScheme());
        assertEquals(true, uriRef15.hasAuthority());
        assertEquals("a", uriRef15.getAuthority().toString());
        assertEquals(null, uriRef15.getUserinfo());
        assertEquals("a", uriRef15.getHost().toString());
        assertEquals("a", uriRef15.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef15.getHost().getType());
        assertEquals(-1, uriRef15.getPort());
        assertEquals("/b/c/d;p", uriRef15.getPath());
        assertEquals("q", uriRef15.getQuery());
        assertEquals(null, uriRef15.getFragment());

        URIReference uriRef16 = URIReference.parse("http://a/b/c/d;p?q").resolve(".");
        assertEquals("http://a/b/c/", uriRef16.toString());
        assertEquals(false, uriRef16.isRelativeReference());
        assertEquals("http", uriRef16.getScheme());
        assertEquals(true, uriRef16.hasAuthority());
        assertEquals("a", uriRef16.getAuthority().toString());
        assertEquals(null, uriRef16.getUserinfo());
        assertEquals("a", uriRef16.getHost().toString());
        assertEquals("a", uriRef16.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef16.getHost().getType());
        assertEquals(-1, uriRef16.getPort());
        assertEquals("/b/c/", uriRef16.getPath());
        assertEquals(null, uriRef16.getQuery());
        assertEquals(null, uriRef16.getFragment());

        URIReference uriRef17 = URIReference.parse("http://a/b/c/d;p?q").resolve("./");
        assertEquals("http://a/b/c/", uriRef17.toString());
        assertEquals(false, uriRef17.isRelativeReference());
        assertEquals("http", uriRef17.getScheme());
        assertEquals(true, uriRef17.hasAuthority());
        assertEquals("a", uriRef17.getAuthority().toString());
        assertEquals(null, uriRef17.getUserinfo());
        assertEquals("a", uriRef17.getHost().toString());
        assertEquals("a", uriRef17.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef17.getHost().getType());
        assertEquals(-1, uriRef17.getPort());
        assertEquals("/b/c/", uriRef17.getPath());
        assertEquals(null, uriRef17.getQuery());
        assertEquals(null, uriRef17.getFragment());

        URIReference uriRef18 = URIReference.parse("http://a/b/c/d;p?q").resolve("..");
        assertEquals("http://a/b/", uriRef18.toString());
        assertEquals(false, uriRef18.isRelativeReference());
        assertEquals("http", uriRef18.getScheme());
        assertEquals(true, uriRef18.hasAuthority());
        assertEquals("a", uriRef18.getAuthority().toString());
        assertEquals(null, uriRef18.getUserinfo());
        assertEquals("a", uriRef18.getHost().toString());
        assertEquals("a", uriRef18.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef18.getHost().getType());
        assertEquals(-1, uriRef18.getPort());
        assertEquals("/b/", uriRef18.getPath());
        assertEquals(null, uriRef18.getQuery());
        assertEquals(null, uriRef18.getFragment());

        URIReference uriRef19 = URIReference.parse("http://a/b/c/d;p?q").resolve("../");
        assertEquals("http://a/b/", uriRef19.toString());
        assertEquals(false, uriRef19.isRelativeReference());
        assertEquals("http", uriRef19.getScheme());
        assertEquals(true, uriRef19.hasAuthority());
        assertEquals("a", uriRef19.getAuthority().toString());
        assertEquals(null, uriRef19.getUserinfo());
        assertEquals("a", uriRef19.getHost().toString());
        assertEquals("a", uriRef19.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef19.getHost().getType());
        assertEquals(-1, uriRef19.getPort());
        assertEquals("/b/", uriRef19.getPath());
        assertEquals(null, uriRef19.getQuery());
        assertEquals(null, uriRef19.getFragment());

        URIReference uriRef20 = URIReference.parse("http://a/b/c/d;p?q").resolve("../g");
        assertEquals("http://a/b/g", uriRef20.toString());
        assertEquals(false, uriRef20.isRelativeReference());
        assertEquals("http", uriRef20.getScheme());
        assertEquals(true, uriRef20.hasAuthority());
        assertEquals("a", uriRef20.getAuthority().toString());
        assertEquals(null, uriRef20.getUserinfo());
        assertEquals("a", uriRef20.getHost().toString());
        assertEquals("a", uriRef20.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef20.getHost().getType());
        assertEquals(-1, uriRef20.getPort());
        assertEquals("/b/g", uriRef20.getPath());
        assertEquals(null, uriRef20.getQuery());
        assertEquals(null, uriRef20.getFragment());

        URIReference uriRef21 = URIReference.parse("http://a/b/c/d;p?q").resolve("../..");
        assertEquals("http://a/", uriRef21.toString());
        assertEquals(false, uriRef21.isRelativeReference());
        assertEquals("http", uriRef21.getScheme());
        assertEquals(true, uriRef21.hasAuthority());
        assertEquals("a", uriRef21.getAuthority().toString());
        assertEquals(null, uriRef21.getUserinfo());
        assertEquals("a", uriRef21.getHost().toString());
        assertEquals("a", uriRef21.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef21.getHost().getType());
        assertEquals(-1, uriRef21.getPort());
        assertEquals("/", uriRef21.getPath());
        assertEquals(null, uriRef21.getQuery());
        assertEquals(null, uriRef21.getFragment());

        URIReference uriRef22 = URIReference.parse("http://a/b/c/d;p?q").resolve("../../");
        assertEquals("http://a/", uriRef22.toString());
        assertEquals(false, uriRef22.isRelativeReference());
        assertEquals("http", uriRef22.getScheme());
        assertEquals(true, uriRef22.hasAuthority());
        assertEquals("a", uriRef22.getAuthority().toString());
        assertEquals(null, uriRef22.getUserinfo());
        assertEquals("a", uriRef22.getHost().toString());
        assertEquals("a", uriRef22.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef22.getHost().getType());
        assertEquals(-1, uriRef22.getPort());
        assertEquals("/", uriRef22.getPath());
        assertEquals(null, uriRef22.getQuery());
        assertEquals(null, uriRef22.getFragment());

        URIReference uriRef23 = URIReference.parse("http://a/b/c/d;p?q").resolve("../../g");
        assertEquals("http://a/g", uriRef23.toString());
        assertEquals(false, uriRef23.isRelativeReference());
        assertEquals("http", uriRef23.getScheme());
        assertEquals(true, uriRef23.hasAuthority());
        assertEquals("a", uriRef23.getAuthority().toString());
        assertEquals(null, uriRef23.getUserinfo());
        assertEquals("a", uriRef23.getHost().toString());
        assertEquals("a", uriRef23.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef23.getHost().getType());
        assertEquals(-1, uriRef23.getPort());
        assertEquals("/g", uriRef23.getPath());
        assertEquals(null, uriRef23.getQuery());
        assertEquals(null, uriRef23.getFragment());

        URIReference uriRef24 = URIReference.parse("http://a/b/c/d;p?q").resolve("g?y/./x");
        assertEquals("http://a/b/c/g?y/./x", uriRef24.toString());
        assertEquals(false, uriRef24.isRelativeReference());
        assertEquals("http", uriRef24.getScheme());
        assertEquals(true, uriRef24.hasAuthority());
        assertEquals("a", uriRef24.getAuthority().toString());
        assertEquals(null, uriRef24.getUserinfo());
        assertEquals("a", uriRef24.getHost().toString());
        assertEquals("a", uriRef24.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef24.getHost().getType());
        assertEquals(-1, uriRef24.getPort());
        assertEquals("/b/c/g", uriRef24.getPath());
        assertEquals("y/./x", uriRef24.getQuery());
        assertEquals(null, uriRef24.getFragment());

        URIReference uriRef25 = URIReference.parse("http://a/b/c/d;p?q").resolve("g?y/../x");
        assertEquals("http://a/b/c/g?y/../x", uriRef25.toString());
        assertEquals(false, uriRef25.isRelativeReference());
        assertEquals("http", uriRef25.getScheme());
        assertEquals(true, uriRef25.hasAuthority());
        assertEquals("a", uriRef25.getAuthority().toString());
        assertEquals(null, uriRef25.getUserinfo());
        assertEquals("a", uriRef25.getHost().toString());
        assertEquals("a", uriRef25.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef25.getHost().getType());
        assertEquals(-1, uriRef25.getPort());
        assertEquals("/b/c/g", uriRef25.getPath());
        assertEquals("y/../x", uriRef25.getQuery());
        assertEquals(null, uriRef25.getFragment());

        URIReference uriRef26 = URIReference.parse("http://a/b/c/d;p?q").resolve("g#s/./x");
        assertEquals("http://a/b/c/g#s/./x", uriRef26.toString());
        assertEquals(false, uriRef26.isRelativeReference());
        assertEquals("http", uriRef26.getScheme());
        assertEquals(true, uriRef26.hasAuthority());
        assertEquals("a", uriRef26.getAuthority().toString());
        assertEquals(null, uriRef26.getUserinfo());
        assertEquals("a", uriRef26.getHost().toString());
        assertEquals("a", uriRef26.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef26.getHost().getType());
        assertEquals(-1, uriRef26.getPort());
        assertEquals("/b/c/g", uriRef26.getPath());
        assertEquals(null, uriRef26.getQuery());
        assertEquals("s/./x", uriRef26.getFragment());

        URIReference uriRef27 = URIReference.parse("http://a/b/c/d;p?q").resolve("g#s/../x");
        assertEquals("http://a/b/c/g#s/../x", uriRef27.toString());
        assertEquals(false, uriRef27.isRelativeReference());
        assertEquals("http", uriRef27.getScheme());
        assertEquals(true, uriRef27.hasAuthority());
        assertEquals("a", uriRef27.getAuthority().toString());
        assertEquals(null, uriRef27.getUserinfo());
        assertEquals("a", uriRef27.getHost().toString());
        assertEquals("a", uriRef27.getHost().getValue());
        assertEquals(HostType.REGNAME, uriRef27.getHost().getType());
        assertEquals(-1, uriRef27.getPort());
        assertEquals("/b/c/g", uriRef27.getPath());
        assertEquals(null, uriRef27.getQuery());
        assertEquals("s/../x", uriRef27.getFragment());

        assertThrowsNPE(
            "The input string must not be null.",
            () -> URIReference.parse("http://a/b/c/d;p?q").resolve((String)null));

        assertThrowsISE(
            "The base URI must have a scheme.",
            () -> URIReference.parse("/a/b/c/d;p?q").resolve("g"));

        assertThrowsISE(
            "The base URI must not have a fragment.",
            () -> URIReference.parse("http://a/b/c/d;p?q#s").resolve("g"));
    }


    @Test
    public void test_normalize()
    {
        URIReference uriRef1 = URIReference.parse("hTTp://example.com/").normalize();
        assertEquals("http://example.com/", uriRef1.toString());
        assertEquals(false, uriRef1.isRelativeReference());
        assertEquals("http", uriRef1.getScheme());
        assertEquals(true, uriRef1.hasAuthority());
        assertEquals("example.com", uriRef1.getAuthority().toString());
        assertEquals(null, uriRef1.getUserinfo());
        assertEquals("example.com", uriRef1.getHost().toString());
        assertEquals("example.com", uriRef1.getHost().getValue());
        assertEquals(REGNAME, uriRef1.getHost().getType());
        assertEquals(-1, uriRef1.getPort());
        assertEquals("/", uriRef1.getPath());
        assertEquals(null, uriRef1.getQuery());
        assertEquals(null, uriRef1.getFragment());

        URIReference uriRef2 = URIReference.parse("http://example.com/").normalize();
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("example.com", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("example.com", uriRef2.getHost().toString());
        assertEquals("example.com", uriRef2.getHost().getValue());
        assertEquals(REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = URIReference.parse("http://%75ser@example.com/").normalize();
        assertEquals("http://user@example.com/", uriRef3.toString());
        assertEquals(false, uriRef3.isRelativeReference());
        assertEquals("http", uriRef3.getScheme());
        assertEquals(true, uriRef3.hasAuthority());
        assertEquals("user@example.com", uriRef3.getAuthority().toString());
        assertEquals("user", uriRef3.getUserinfo());
        assertEquals("example.com", uriRef3.getHost().toString());
        assertEquals("example.com", uriRef3.getHost().getValue());
        assertEquals(REGNAME, uriRef3.getHost().getType());
        assertEquals(-1, uriRef3.getPort());
        assertEquals("/", uriRef3.getPath());
        assertEquals(null, uriRef3.getQuery());
        assertEquals(null, uriRef3.getFragment());

        URIReference uriRef4 = URIReference.parse("http://%e3%83%a6%e3%83%bc%e3%82%b6%e3%83%bc@example.com/").normalize();
        assertEquals("http://%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC@example.com/", uriRef4.toString());
        assertEquals(false, uriRef4.isRelativeReference());
        assertEquals("http", uriRef4.getScheme());
        assertEquals(true, uriRef4.hasAuthority());
        assertEquals("%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC@example.com", uriRef4.getAuthority().toString());
        assertEquals("%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC", uriRef4.getUserinfo());
        assertEquals("example.com", uriRef4.getHost().toString());
        assertEquals("example.com", uriRef4.getHost().getValue());
        assertEquals(REGNAME, uriRef4.getHost().getType());
        assertEquals(-1, uriRef4.getPort());
        assertEquals("/", uriRef4.getPath());
        assertEquals(null, uriRef4.getQuery());
        assertEquals(null, uriRef4.getFragment());

        URIReference uriRef5 = URIReference.parse("http://%65%78%61%6D%70%6C%65.com/").normalize();
        assertEquals("http://example.com/", uriRef5.toString());
        assertEquals(false, uriRef5.isRelativeReference());
        assertEquals("http", uriRef5.getScheme());
        assertEquals(true, uriRef5.hasAuthority());
        assertEquals("example.com", uriRef5.getAuthority().toString());
        assertEquals(null, uriRef5.getUserinfo());
        assertEquals("example.com", uriRef5.getHost().toString());
        assertEquals("example.com", uriRef5.getHost().getValue());
        assertEquals(REGNAME, uriRef5.getHost().getType());
        assertEquals(-1, uriRef5.getPort());
        assertEquals("/", uriRef5.getPath());
        assertEquals(null, uriRef5.getQuery());
        assertEquals(null, uriRef5.getFragment());

        URIReference uriRef6 = URIReference.parse("http://%e4%be%8b.com/").normalize();
        assertEquals("http://%E4%BE%8B.com/", uriRef6.toString());
        assertEquals(false, uriRef6.isRelativeReference());
        assertEquals("http", uriRef6.getScheme());
        assertEquals(true, uriRef6.hasAuthority());
        assertEquals("%E4%BE%8B.com", uriRef6.getAuthority().toString());
        assertEquals(null, uriRef6.getUserinfo());
        assertEquals("%E4%BE%8B.com", uriRef6.getHost().toString());
        assertEquals("%E4%BE%8B.com", uriRef6.getHost().getValue());
        assertEquals(REGNAME, uriRef6.getHost().getType());
        assertEquals(-1, uriRef6.getPort());
        assertEquals("/", uriRef6.getPath());
        assertEquals(null, uriRef6.getQuery());
        assertEquals(null, uriRef6.getFragment());

        URIReference uriRef7 = URIReference.parse("http://LOCALhost/").normalize();
        assertEquals("http://localhost/", uriRef7.toString());
        assertEquals(false, uriRef7.isRelativeReference());
        assertEquals("http", uriRef7.getScheme());
        assertEquals(true, uriRef7.hasAuthority());
        assertEquals("localhost", uriRef7.getAuthority().toString());
        assertEquals(null, uriRef7.getUserinfo());
        assertEquals("localhost", uriRef7.getHost().toString());
        assertEquals("localhost", uriRef7.getHost().getValue());
        assertEquals(REGNAME, uriRef7.getHost().getType());
        assertEquals(-1, uriRef7.getPort());
        assertEquals("/", uriRef7.getPath());
        assertEquals(null, uriRef7.getQuery());
        assertEquals(null, uriRef7.getFragment());

        URIReference uriRef8 = URIReference.parse("http://example.com").normalize();
        assertEquals("http://example.com/", uriRef8.toString());
        assertEquals(false, uriRef8.isRelativeReference());
        assertEquals("http", uriRef8.getScheme());
        assertEquals(true, uriRef8.hasAuthority());
        assertEquals("example.com", uriRef8.getAuthority().toString());
        assertEquals(null, uriRef8.getUserinfo());
        assertEquals("example.com", uriRef8.getHost().toString());
        assertEquals("example.com", uriRef8.getHost().getValue());
        assertEquals(REGNAME, uriRef8.getHost().getType());
        assertEquals(-1, uriRef8.getPort());
        assertEquals("/", uriRef8.getPath());
        assertEquals(null, uriRef8.getQuery());
        assertEquals(null, uriRef8.getFragment());

        URIReference uriRef9 = URIReference.parse("http://example.com/%61/%62/%63/").normalize();
        assertEquals("http://example.com/a/b/c/", uriRef9.toString());
        assertEquals(false, uriRef9.isRelativeReference());
        assertEquals("http", uriRef9.getScheme());
        assertEquals(true, uriRef9.hasAuthority());
        assertEquals("example.com", uriRef9.getAuthority().toString());
        assertEquals(null, uriRef9.getUserinfo());
        assertEquals("example.com", uriRef9.getHost().toString());
        assertEquals("example.com", uriRef9.getHost().getValue());
        assertEquals(REGNAME, uriRef9.getHost().getType());
        assertEquals(-1, uriRef9.getPort());
        assertEquals("/a/b/c/", uriRef9.getPath());
        assertEquals(null, uriRef9.getQuery());
        assertEquals(null, uriRef9.getFragment());

        URIReference uriRef10 = URIReference.parse("http://example.com/%e3%83%91%e3%82%b9/").normalize();
        assertEquals("http://example.com/%E3%83%91%E3%82%B9/", uriRef10.toString());
        assertEquals(false, uriRef10.isRelativeReference());
        assertEquals("http", uriRef10.getScheme());
        assertEquals(true, uriRef10.hasAuthority());
        assertEquals("example.com", uriRef10.getAuthority().toString());
        assertEquals(null, uriRef10.getUserinfo());
        assertEquals("example.com", uriRef10.getHost().toString());
        assertEquals("example.com", uriRef10.getHost().getValue());
        assertEquals(REGNAME, uriRef10.getHost().getType());
        assertEquals(-1, uriRef10.getPort());
        assertEquals("/%E3%83%91%E3%82%B9/", uriRef10.getPath());
        assertEquals(null, uriRef10.getQuery());
        assertEquals(null, uriRef10.getFragment());

        URIReference uriRef11 = URIReference.parse("http://example.com/a/b/c/../d/").normalize();
        assertEquals("http://example.com/a/b/d/", uriRef11.toString());
        assertEquals(false, uriRef11.isRelativeReference());
        assertEquals("http", uriRef11.getScheme());
        assertEquals(true, uriRef11.hasAuthority());
        assertEquals("example.com", uriRef11.getAuthority().toString());
        assertEquals(null, uriRef11.getUserinfo());
        assertEquals("example.com", uriRef11.getHost().toString());
        assertEquals("example.com", uriRef11.getHost().getValue());
        assertEquals(REGNAME, uriRef11.getHost().getType());
        assertEquals(-1, uriRef11.getPort());
        assertEquals("/a/b/d/", uriRef11.getPath());
        assertEquals(null, uriRef11.getQuery());
        assertEquals(null, uriRef11.getFragment());

        URIReference uriRef12 = URIReference.parse("http://example.com:80/").normalize();
        assertEquals("http://example.com/", uriRef12.toString());
        assertEquals(false, uriRef12.isRelativeReference());
        assertEquals("http", uriRef12.getScheme());
        assertEquals(true, uriRef12.hasAuthority());
        assertEquals("example.com", uriRef12.getAuthority().toString());
        assertEquals(null, uriRef12.getUserinfo());
        assertEquals("example.com", uriRef12.getHost().toString());
        assertEquals("example.com", uriRef12.getHost().getValue());
        assertEquals(REGNAME, uriRef12.getHost().getType());
        assertEquals(-1, uriRef12.getPort());
        assertEquals("/", uriRef12.getPath());
        assertEquals(null, uriRef12.getQuery());
        assertEquals(null, uriRef12.getFragment());

        assertThrowsISE(
            "A relative references must be resolved before it can be normalized.",
            () -> URIReference.parse("//example.com").normalize());
    }


    @Test
    public void test_compareTo()
    {
        assertEquals(0, URIReference.parse("http://example.com/a/b/c/").compareTo(URIReference.parse("http://example.com/a/b/c/")));

        assertTrue(URIReference.parse("127.0.0.1").compareTo(URIReference.parse("http://example.com/a/b/c/")) < 0);

        assertThrowsNPE("A null value is not comparable.", () -> URIReference.parse("http://example.com/a/b/c/").compareTo(null));
    }
}
