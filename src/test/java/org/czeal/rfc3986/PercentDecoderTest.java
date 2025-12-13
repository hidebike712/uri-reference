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
import org.junit.jupiter.api.Test;


public class PercentDecoderTest
{
    @Test
    public void test_decode()
    {
        assertEquals("aA", PercentDecoder.decode("a%41", UTF_8));
        assertEquals("aア", PercentDecoder.decode("a%e3%82%A2", UTF_8));
        assertEquals("aアbc", PercentDecoder.decode("a%e3%82%A2bc", UTF_8));

        assertThrowsIAE(
            "The character \"X\" at the index 2 in the value \"a%XX\" is invalid as a hex digit.",
            () -> PercentDecoder.decode("a%XX", UTF_8));

        assertThrowsIAE(
            "The percent symbol \"%\" at the index 1 in the input value \"a%A\" is not followed by two characters.",
            () -> PercentDecoder.decode("a%A", UTF_8));
    }
}
