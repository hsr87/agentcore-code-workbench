package com.example.cwesample

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** Minimal app that displays how many times the button has been pressed. Used to verify instrumentation tests and agent interaction. */
class MainActivity : AppCompatActivity() {
    private var count = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val label = findViewById<TextView>(R.id.counter)
        findViewById<Button>(R.id.increment).setOnClickListener {
            count += 1
            label.text = getString(R.string.count_format, count)
        }
    }
}
