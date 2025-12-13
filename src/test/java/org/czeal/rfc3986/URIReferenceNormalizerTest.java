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
import static org.czeal.rfc3986.HostType.REGNAME;
import static org.czeal.rfc3986.TestUtils.assertThrowsISE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class URIReferenceNormalizerTest
{
    @Test
    public void test_normalize()
    {
        URIReference uriRef1 = new URIReferenceNormalizer().normalize(URIReference.parse("hTTp://example.com/", UTF_8));
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

        URIReference uriRef2 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com/", UTF_8));
        assertEquals(true, uriRef2.hasAuthority());
        assertEquals("example.com", uriRef2.getAuthority().toString());
        assertEquals(null, uriRef2.getUserinfo());
        assertEquals("example.com", uriRef2.getHost().toString());
        assertEquals("example.com", uriRef2.getHost().getValue());
        assertEquals(REGNAME, uriRef2.getHost().getType());
        assertEquals(-1, uriRef2.getPort());
        assertEquals(null, uriRef2.getQuery());
        assertEquals(null, uriRef2.getFragment());

        URIReference uriRef3 = new URIReferenceNormalizer().normalize(URIReference.parse("http://%75ser@example.com/", UTF_8));
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

        URIReference uriRef4 = new URIReferenceNormalizer().normalize(URIReference.parse("http://%e3%83%a6%e3%83%bc%e3%82%b6%e3%83%bc@example.com/", UTF_8));
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

        URIReference uriRef5 = new URIReferenceNormalizer().normalize(URIReference.parse("http://%65%78%61%6D%70%6C%65.com/", UTF_8));
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

        URIReference uriRef6 = new URIReferenceNormalizer().normalize(URIReference.parse("http://%e4%be%8b.com/", UTF_8));
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

        URIReference uriRef7 = new URIReferenceNormalizer().normalize(URIReference.parse("http://LOCALhost/", UTF_8));
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

        URIReference uriRef8 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com", UTF_8));
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

        URIReference uriRef9 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com/%61/%62/%63/", UTF_8));
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

        URIReference uriRef10 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com/%e3%83%91%e3%82%b9/", UTF_8));
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

        URIReference uriRef11 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com/a/b/c/../d/", UTF_8));
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

        URIReference uriRef12 = new URIReferenceNormalizer().normalize(URIReference.parse("http://example.com:80/", UTF_8));
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
            () -> new URIReferenceNormalizer().normalize(URIReference.parse("//example.com", UTF_8)));
    }
}
