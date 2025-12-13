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
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.REGNAME;
import org.junit.jupiter.api.Test;


public class HostNormalizerTest
{
    @Test
    public void test_normalize()
    {
        Host normalized1 = new HostNormalizer().normalize(new Host(REGNAME, "HOst"), UTF_8);
        assertEquals(REGNAME, normalized1.getType());
        assertEquals("host", normalized1.getValue());

        Host normalized2 = new HostNormalizer().normalize(new Host(REGNAME, "hos%74"), UTF_8);
        assertEquals(REGNAME, normalized2.getType());
        assertEquals("host", normalized2.getValue());

        Host normalized3 = new HostNormalizer().normalize(new Host(REGNAME, "1%2E1%2E1%2E1"), UTF_8);
        assertEquals(IPV4, normalized3.getType());
        assertEquals("1.1.1.1", normalized3.getValue());

        Host normalized4 = new HostNormalizer().normalize(new Host(REGNAME, "[%32%30%30%31:%30%64%62%38:%38%35%61%33:%30%30%30%30:%30%30%30%30:%38%61%32%65:%30%33%37%30:%37%33%33%34]"), UTF_8);
        assertEquals(IPV6, normalized4.getType());
        assertEquals("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", normalized4.getValue());

        Host normalized5 = new HostNormalizer().normalize(new Host(REGNAME, "[%76%31.%66%65%38%30::%61+%65%6E%31]"), UTF_8);
        assertEquals(IPVFUTURE, normalized5.getType());
        assertEquals("[v1.fe80::a+en1]", normalized5.getValue());

        Host normalized6 = new HostNormalizer().normalize(new Host(REGNAME, ""), UTF_8);
        assertEquals(REGNAME, normalized6.getType());
        assertEquals("", normalized6.getValue());

        Host normalized7 = new HostNormalizer().normalize(new Host(REGNAME, null), UTF_8);
        assertEquals(REGNAME, normalized7.getType());
        assertEquals(null, normalized7.getValue());
    }
}
