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


public class UserinfoValidatorTest
{
    @Test
    public void test_validate()
    {
        new UserinfoValidator().validate("userinfo", UTF_8);
        new UserinfoValidator().validate("user:password", UTF_8);
        new UserinfoValidator().validate("", UTF_8);
        new UserinfoValidator().validate(null, UTF_8);

        assertThrowsIAE(
            "The userinfo value \"user password\" has an invalid character \" \" at the index 4.",
            () -> new UserinfoValidator().validate("user password", UTF_8));

        assertThrowsIAE(
            "The userinfo value \"user#password\" has an invalid character \"#\" at the index 4.",
            () -> new UserinfoValidator().validate("user#password", UTF_8));

        assertThrowsIAE(
            "The userinfo value \"user/password\" has an invalid character \"/\" at the index 4.",
            () -> new UserinfoValidator().validate("user/password", UTF_8));

        assertThrowsIAE(
            "The userinfo value \"%XXuserinfo\" has an invalid hex digit \"X\" at the index 1.",
            () -> new UserinfoValidator().validate("%XXuserinfo", UTF_8));
    }
}
