// Denom.org
// Author:  Mihail Buhlin

package org.denom.testrunner;

import java.lang.annotation.*;

/**
 * Annotation for test suites and test cases to set test name and description.
 */
@Target( value = {ElementType.TYPE, ElementType.METHOD} )
@Retention( value = RetentionPolicy.RUNTIME )
public @interface TestDescription
{
	String name();
	String description();
}