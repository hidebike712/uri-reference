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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import org.junit.jupiter.api.Test;


public class PortTest
{
    private static final String PORT1 = "80";
    private static final String PORT2 = "";
    private static final String PORT3 = null;
    private static final String PORT4 = "-1";
    private static final String PORT5 = "A";


    @Test
    public void test_parse()
    {
        assertDoesNotThrow(() -> new PortValidator().validate(PORT1));
        assertDoesNotThrow(() -> new PortValidator().validate(PORT2));
        assertDoesNotThrow(() -> new PortValidator().validate(PORT3));

        assertThrowsIAE(
            "The port value \"-1\" has an invalid character \"-\" at the index 0.",
            () -> new PortValidator().validate(PORT4));

        assertThrowsIAE(
            "The port value \"A\" has an invalid character \"A\" at the index 0.",
            () -> new PortValidator().validate(PORT5));
    }
}
