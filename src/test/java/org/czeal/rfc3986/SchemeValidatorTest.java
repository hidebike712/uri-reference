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
import static org.czeal.rfc3986.TestUtils.assertThrowsNPE;
import org.junit.jupiter.api.Test;


public class SchemeValidatorTest
{
    @Test
    public void test_validate()
    {
        new SchemeValidator().validate("http");
        new SchemeValidator().validate("ftp");
        new SchemeValidator().validate("a+f");

        assertThrowsIAE(
            "The scheme value \"1http\" has an invalid character \"1\" at the index 0.",
            () -> new SchemeValidator().validate("1http"));

        assertThrowsIAE(
            "The scheme value \"http_\" has an invalid character \"_\" at the index 4.",
            () -> new SchemeValidator().validate("http_"));

        assertThrowsIAE(
            "The scheme value must not be empty.", () -> new SchemeValidator().validate(""));

        assertThrowsNPE(
            "The scheme value must not be null.", () -> new SchemeValidator().validate(null));
    }
}
