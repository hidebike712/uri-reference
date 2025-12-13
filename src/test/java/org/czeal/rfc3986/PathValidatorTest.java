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


public class PathValidatorTest
{
    @Test
    public void test_validate()
    {
        //
        // relativeReference = true, hasAuthority = true
        //
        new PathValidator().validate("/segment", UTF_8, true, true);
        new PathValidator().validate("/segment/", UTF_8, true, true);
        new PathValidator().validate("/segment1/segment2", UTF_8, true, true);
        new PathValidator().validate("/", UTF_8, true, true);
        new PathValidator().validate("//", UTF_8, true, true);
        new PathValidator().validate("", UTF_8, true, true);
        new PathValidator().validate(null, UTF_8, true, true);

        assertThrowsIAE(
            "The path must start with a slash.",
            () -> new PathValidator().validate("segment", UTF_8, true, true));

        //
        // relativeReference = false, hasAuthority = false
        //
        new PathValidator().validate("/segment", UTF_8, true, false);
        new PathValidator().validate("/segment/", UTF_8, true, false);
        new PathValidator().validate("/segment1/segment2", UTF_8, true, false);
        new PathValidator().validate("/", UTF_8, true, false);
        new PathValidator().validate("segment", UTF_8, true, false);
        new PathValidator().validate("", UTF_8, true, false);

        assertThrowsIAE(
            "The path segment value must not be empty.",
            () -> new PathValidator().validate("//", UTF_8, true, false));

        assertThrowsIAE(
            "The path must not be empty.",
            () -> new PathValidator().validate(null, UTF_8, true, false));

        //
        // relativeReference = false, hasAuthority = true
        //
        new PathValidator().validate("/segment", UTF_8, false, true);
        new PathValidator().validate("/segment/", UTF_8, false, true);
        new PathValidator().validate("/segment1/segment2", UTF_8, false, true);
        new PathValidator().validate("/", UTF_8, false, true);
        new PathValidator().validate("//", UTF_8, false, true);
        new PathValidator().validate("", UTF_8, false, true);
        new PathValidator().validate(null, UTF_8, false, true);

        assertThrowsIAE(
            "The path must start with a slash.",
            () -> new PathValidator().validate("segment", UTF_8, false, true));

        //
        // relativeReference = false, hasAuthority = true
        //
        new PathValidator().validate("/segment", UTF_8, false, false);
        new PathValidator().validate("/segment/", UTF_8, false, false);
        new PathValidator().validate("/segment1/segment2", UTF_8, false, false);
        new PathValidator().validate("/", UTF_8, false, false);
        new PathValidator().validate("segment", UTF_8, false, false);
        new PathValidator().validate("", UTF_8, false, false);

        assertThrowsIAE(
            "The path segment value must not be empty.",
            () -> new PathValidator().validate("//", UTF_8, false, false));

        assertThrowsIAE(
            "The path must not be empty.",
            () -> new PathValidator().validate(null, UTF_8, false, false));
    }
}
