package com.example.malgaurd

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.colorResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.lazy.grid.GridItemSpan


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = resources.getColor(R.color.dark_primary, null)

        setContent {
            MainApp()
        }
    }
}

@Composable
fun MainApp() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colorResource(id = R.color.dark_primary)),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        // App Name Row
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Start,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Tushar Guard",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                textAlign = TextAlign.Start,
                modifier = Modifier.padding(16.dp)
            )
        }

        Box(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            contentAlignment = Alignment.Center,
        ) {
            ScannerComponent()
        }
        Text(
            text = "Scan Your Device to find hidden threats",
            color = colorResource(id = R.color.green),
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            text = "Last Scan 10 Days Ago",
            color = colorResource(id = R.color.white),
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )

        CardsGrid()
    }
}


@Composable
fun ScannerComponent() {
    val context = LocalContext.current
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .width(240.dp)
            .aspectRatio(1f)
            .background(colorResource(id = R.color.dark_primary), shape = CircleShape)
            .border(
                5.dp,
                colorResource(id = R.color.dark_secondary),
                shape = CircleShape
            )
            .padding(16.dp)

    ) {
        // Green button in the center
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(195.dp)
                .background(colorResource(id = R.color.green), shape = CircleShape)
                .clickable {
                    Toast
                        .makeText(context, "Scanning for viruses...", Toast.LENGTH_SHORT)
                        .show()
                }

        ) {
            Text(
                text = "SCAN",
                color = Color.Black,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
        }
    }
}
@Composable

fun CardComponent(iconRes: Int, title: String, toastMessage: String) {
    val context = LocalContext.current
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                Toast
                    .makeText(context, toastMessage, Toast.LENGTH_SHORT) // Show the toast with passed message
                    .show()
            }
            .border(1.dp, colorResource(id = R.color.dark_secondary))
            .padding(16.dp)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(52.dp)
                .clip(CircleShape)
                .background(colorResource(id = R.color.dark_secondary))
        ) {
            // Icon
            Image(
                painter = painterResource(id = iconRes),
                contentDescription = title,
                contentScale = ContentScale.Fit,
                modifier = Modifier.size(24.dp) // Adjust icon size
            )
        }

        // Title
        Text(
            text = title,
            color = Color.White, // Adjust text color as needed
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 4.dp)
        )
    }
}

@Composable
fun CardsGrid() {
    LazyVerticalGrid(
        columns = GridCells.Fixed(2),
        modifier = Modifier
            .fillMaxSize()
            .background(colorResource(id = R.color.dark_primary))
    ) {
        item {
            CardComponent(
                iconRes = R.drawable.rocket,
                title = "Phishing Detection",
                toastMessage = "Tushar What to do next?"
            )
        }
        item {
            CardComponent(
                iconRes = R.drawable.hacker,
                title = "Hack Alert",
                toastMessage = "ArshadOS was better project idea"
            )
        }
        item {
            CardComponent(
                iconRes = R.drawable.sheild,
                title = "Quarantine",
                toastMessage = "Neal App ka logo ki quality badha"
            )
        }
        item {
            CardComponent(
                iconRes = R.drawable.battery,
                title = "Battery Saver",
                toastMessage = "Nothing to say about me"
            )
        }

        item(span = { GridItemSpan(2) }) {
            WebVersion()
        }
    }
}

@Composable
fun WebVersion() {
    val context = LocalContext.current // Get the current context

    Box(
        modifier = Modifier
            .fillMaxSize()
            .clickable {
                val intent =
                    Intent(Intent.ACTION_VIEW, Uri.parse("https://raahim-portfolio.vercel.app"))
                context.startActivity(intent)
            }
            .border(width = 2.dp, colorResource(id = R.color.dark_secondary))
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    colorResource(id = R.color.dark_primary),
                )
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Start,
                modifier = Modifier
                    .padding(16.dp)

            ) {
                // Icon
                Image(
                    painter = painterResource(id = R.drawable.rocket),
                    contentDescription = "Web Version Icon",
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .size(48.dp)
                        .background(colorResource(id = R.color.dark_secondary), shape = RoundedCornerShape(32.dp))
                        .padding(8.dp)


                )

                // Spacer between icon and text
                Spacer(modifier = Modifier.width(16.dp))

                // Text
                Text(
                    text = "Explore our web version",
                    color = Color.White,
                    style = TextStyle(fontSize = 16.sp)
                )
            }
        }
    }
}


@Preview(showBackground = true)
@Composable
fun PreviewApp() {
    MainApp()
}
