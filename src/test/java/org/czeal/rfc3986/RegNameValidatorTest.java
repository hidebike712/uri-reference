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
import org.junit.jupiter.api.Test;


public class RegNameValidatorTest
{
    @Test
    public void test_validate()
    {
        new RegNameValidator().validate("example.com", UTF_8);
        new RegNameValidator().validate("a_example.com", UTF_8);
        new RegNameValidator().validate("a-example.com", UTF_8);
        new RegNameValidator().validate("%20example.com", UTF_8);

        assertThrowsIAE(
            "The host value \"%XXexample.com\" has an invalid hex digit \"X\" at the index 1.",
            () -> new RegNameValidator().validate("%XXexample.com", UTF_8));

        assertThrowsIAE(
            "The host value \"a@example.com\" has an invalid character \"@\" at the index 1.",
            () -> new RegNameValidator().validate("a@example.com", UTF_8));

        assertThrowsIAE(
            "The host value \"example.com/a\" has an invalid character \"/\" at the index 11.",
            () -> new RegNameValidator().validate("example.com/a", UTF_8));

        assertThrowsIAE(
            "The host value \"example.com?a\" has an invalid character \"?\" at the index 11.",
            () -> new RegNameValidator().validate("example.com?a", UTF_8));

        assertThrowsIAE(
            "The host value \"example.com:a\" has an invalid character \":\" at the index 11.",
            () -> new RegNameValidator().validate("example.com:a", UTF_8));

        assertThrowsIAE(
            "The host value \"例子.测试\" has an invalid character \"例\" at the index 0.",
            () -> new RegNameValidator().validate("例子.测试", UTF_8));
    }
}
