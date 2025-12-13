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


public class FragmentValidatorTest
{
    @Test
    public void test_validate()
    {
        new FragmentValidator().validate("section1", UTF_8);
        new FragmentValidator().validate("fig%20A", UTF_8);
        new FragmentValidator().validate("2.3", UTF_8);
        new FragmentValidator().validate("", UTF_8);
        new FragmentValidator().validate(null, UTF_8);

        assertThrowsIAE(
            "The fragment value \"#fragment\" has an invalid character \"#\" at the index 0.",
            () -> new FragmentValidator().validate("#fragment", UTF_8));

        assertThrowsIAE(
            "The fragment value \" frag\" has an invalid character \" \" at the index 0.",
            () -> new FragmentValidator().validate(" frag", UTF_8));

        assertThrowsIAE(
            "The percent symbol \"%\" at the index 8 in the fragment value \"fragment%1\" is not followed by two characters.",
            () -> new FragmentValidator().validate("fragment%1", UTF_8));

        assertThrowsIAE(
            "The fragment value \"fragment%XX\" has an invalid hex digit \"X\" at the index 9.",
            () -> new FragmentValidator().validate("fragment%XX", UTF_8));
    }
}
