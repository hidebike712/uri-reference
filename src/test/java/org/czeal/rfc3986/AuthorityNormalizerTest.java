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


import static org.czeal.rfc3986.HostType.REGNAME;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class AuthorityNormalizerTest
{
    @Test
    public void test_normalize()
    {
        Authority normalized1 = new AuthorityNormalizer().normalize(
            Authority.parse("userinfoABC@EXAMPLE.com:80"), UTF_8, "http");
        assertEquals("userinfoABC", normalized1.getUserinfo());
        assertEquals(REGNAME, normalized1.getHost().getType());
        assertEquals("example.com", normalized1.getHost().getValue());
        assertEquals(-1, normalized1.getPort());
        assertEquals("userinfoABC@example.com", normalized1.toString());

        Authority normalized2 = new AuthorityNormalizer().normalize(
            Authority.parse("userinfoABC@EXAMPLE.com:443"), UTF_8, "https");
        assertEquals("userinfoABC", normalized2.getUserinfo());
        assertEquals(REGNAME, normalized2.getHost().getType());
        assertEquals("example.com", normalized2.getHost().getValue());
        assertEquals(443, normalized2.getPort());
        assertEquals("userinfoABC@example.com:443", normalized2.toString());

        Authority normalized3 = new AuthorityNormalizer().normalize(null, UTF_8, "http");
        assertEquals(null, normalized3);
    }
}
