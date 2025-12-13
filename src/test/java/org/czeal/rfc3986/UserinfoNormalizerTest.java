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
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;


public class UserinfoNormalizerTest
{
    @Test
    public void test_normalize()
    {
        assertEquals("userINFO", new UserinfoNormalizer().normalize("userINFO", UTF_8));
        assertEquals("userinfo", new UserinfoNormalizer().normalize("userinf%6F", UTF_8));
        assertEquals("", new UserinfoNormalizer().normalize("", UTF_8));
        assertEquals(null, new UserinfoNormalizer().normalize(null, UTF_8));
    }
}
