package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.CompareArrows
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.i18n.LocalAppStrings
import com.example.i18n.stringsFor
import com.example.ui.screens.ComparatorScreen
import com.example.ui.screens.DiagnosticScreen
import com.example.ui.screens.SettingsScreen
import com.example.ui.theme.FodDetectorTheme
import com.example.viewmodel.ComparatorViewModel
import com.example.viewmodel.DiagnosticViewModel
import com.example.viewmodel.SettingsViewModel

private const val ROUTE_DIAGNOSTIC = "diagnostic"
private const val ROUTE_COMPARATOR = "comparator"
private const val ROUTE_SETTINGS = "settings"

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Mandatory Step 1: Configure Firebase App Check with launch intent before any UI or ViewModels
        configureAppCheck(this, intent)

        enableEdgeToEdge()
        setContent {
            FodDetectorTheme {
                FodDetectorApp()
            }
        }
    }
}

private data class NavTab(
    val route: String,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
)

@Composable
fun FodDetectorApp(
    diagnosticVm: DiagnosticViewModel = viewModel(),
    comparatorVm: ComparatorViewModel = viewModel(),
    settingsVm: SettingsViewModel = viewModel()
) {
    val userSettings by settingsVm.settings.collectAsStateWithLifecycle()
    val allFilesGranted by settingsVm.allFilesGranted.collectAsStateWithLifecycle()
    val strings = stringsFor(userSettings.language)

    CompositionLocalProvider(LocalAppStrings provides strings) {
        val navController = rememberNavController()
        val backStack by navController.currentBackStackEntryAsState()
        val currentRoute = backStack?.destination?.route ?: ROUTE_DIAGNOSTIC

        val tabs = listOf(
            NavTab(
                route = ROUTE_DIAGNOSTIC,
                label = strings.tabDiagnostic,
                selectedIcon = Icons.Filled.Fingerprint,
                unselectedIcon = Icons.Outlined.Fingerprint,
                testTag = "nav_diagnostic"
            ),
            NavTab(
                route = ROUTE_COMPARATOR,
                label = strings.tabComparator,
                selectedIcon = Icons.Filled.CompareArrows,
                unselectedIcon = Icons.Outlined.CompareArrows,
                testTag = "nav_comparator"
            ),
            NavTab(
                route = ROUTE_SETTINGS,
                label = strings.tabSettings,
                selectedIcon = Icons.Filled.Settings,
                unselectedIcon = Icons.Outlined.Settings,
                testTag = "nav_settings"
            )
        )

        val navigateToTab: (String) -> Unit = { route ->
            navController.navigate(route) {
                popUpTo(navController.graph.findStartDestination().id) {
                    saveState = true
                }
                launchSingleTop = true
                restoreState = true
            }
        }

        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val useRail = maxWidth >= 600.dp

            Scaffold(
                modifier = Modifier.fillMaxSize(),
                contentWindowInsets = WindowInsets.safeDrawing,
                bottomBar = {
                    if (!useRail) {
                        NavigationBar {
                            tabs.forEach { tab ->
                                val selected = currentRoute == tab.route
                                NavigationBarItem(
                                    selected = selected,
                                    onClick = { navigateToTab(tab.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                            contentDescription = tab.label
                                        )
                                    },
                                    label = { Text(tab.label) },
                                    modifier = Modifier.testTag(tab.testTag)
                                )
                            }
                        }
                    }
                }
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    if (useRail) {
                        NavigationRail {
                            tabs.forEach { tab ->
                                val selected = currentRoute == tab.route
                                NavigationRailItem(
                                    selected = selected,
                                    onClick = { navigateToTab(tab.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                            contentDescription = tab.label
                                        )
                                    },
                                    label = { Text(tab.label) },
                                    modifier = Modifier.testTag(tab.testTag)
                                )
                            }
                        }
                    }

                    NavHost(
                        navController = navController,
                        startDestination = ROUTE_DIAGNOSTIC,
                        modifier = Modifier.fillMaxSize()
                    ) {
                        composable(ROUTE_DIAGNOSTIC) {
                            DiagnosticScreen(
                                viewModel = diagnosticVm,
                                rootEnabled = userSettings.rootEnabled,
                                allFilesGranted = allFilesGranted,
                                language = userSettings.language
                            )
                        }
                        composable(ROUTE_COMPARATOR) {
                            ComparatorScreen(
                                viewModel = comparatorVm,
                                allFilesGranted = allFilesGranted,
                                language = userSettings.language
                            )
                        }
                        composable(ROUTE_SETTINGS) {
                            SettingsScreen(viewModel = settingsVm)
                        }
                    }
                }
            }
        }
    }
}
