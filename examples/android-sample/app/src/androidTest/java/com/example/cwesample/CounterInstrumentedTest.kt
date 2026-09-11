package com.example.cwesample

import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CounterInstrumentedTest {
    @get:Rule val rule = ActivityScenarioRule(MainActivity::class.java)

    @Test fun startsAtZero() { onView(withId(R.id.counter)).check(matches(withText("Count: 0"))) }

    @Test fun incrementsOnClick() {
        onView(withId(R.id.increment)).perform(click()).perform(click())
        onView(withId(R.id.counter)).check(matches(withText("Count: 2")))
    }
}
