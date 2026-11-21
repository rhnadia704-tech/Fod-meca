package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Immutable
data class FodStatusColors(
    val confirmed: Color,
    val confirmedContainer: Color,
    val observed: Color,
    val observedContainer: Color,
    val suspect: Color,
    val suspectContainer: Color,
    val failed: Color,
    val failedContainer: Color,
    val unknown: Color,
    val unknownContainer: Color
)

val LocalFodStatusColors = staticCompositionLocalOf {
    FodStatusColors(
        confirmed = StatusConfirmedLight,
        confirmedContainer = StatusConfirmedContainerLight,
        observed = StatusObservedLight,
        observedContainer = StatusObservedContainerLight,
        suspect = StatusSuspectLight,
        suspectContainer = StatusSuspectContainerLight,
        failed = StatusFailedLight,
        failedContainer = StatusFailedContainerLight,
        unknown = StatusUnknownLight,
        unknownContainer = StatusUnknownContainerLight
    )
}

private val DarkColorScheme = darkColorScheme(
    primary = LabPrimaryDark,
    onPrimary = LabOnPrimaryDark,
    primaryContainer = Color(0xFF0C4A6E),
    onPrimaryContainer = Color(0xFFE0F2FE),
    secondary = LabSecondaryDark,
    onSecondary = Color(0xFF042F2E),
    secondaryContainer = Color(0xFF134E4A),
    onSecondaryContainer = Color(0xFFCCFBF1),
    tertiary = LabTertiaryDark,
    background = LabBgDark,
    onBackground = LabTextPrimaryDark,
    surface = LabSurfaceDark,
    onSurface = LabTextPrimaryDark,
    surfaceVariant = LabSurfaceElevatedDark,
    onSurfaceVariant = LabTextSecondaryDark,
    outline = LabOutlineDark,
    error = StatusFailedDark,
    errorContainer = StatusFailedContainerDark,
    onErrorContainer = Color(0xFFFEE2E2)
)

private val LightColorScheme = lightColorScheme(
    primary = LabPrimaryLight,
    onPrimary = LabOnPrimaryLight,
    primaryContainer = Color(0xFFE0F2FE),
    onPrimaryContainer = Color(0xFF0C4A6E),
    secondary = LabSecondaryLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCCFBF1),
    onSecondaryContainer = Color(0xFF134E4A),
    tertiary = LabTertiaryLight,
    background = LabBgLight,
    onBackground = LabTextPrimaryLight,
    surface = LabSurfaceLight,
    onSurface = LabTextPrimaryLight,
    surfaceVariant = LabSurfaceElevatedLight,
    onSurfaceVariant = LabTextSecondaryLight,
    outline = LabOutlineLight,
    error = StatusFailedLight,
    errorContainer = StatusFailedContainerLight,
    onErrorContainer = Color(0xFF7F1D1D)
)

private val DarkStatusColors = FodStatusColors(
    confirmed = StatusConfirmedDark,
    confirmedContainer = StatusConfirmedContainerDark,
    observed = StatusObservedDark,
    observedContainer = StatusObservedContainerDark,
    suspect = StatusSuspectDark,
    suspectContainer = StatusSuspectContainerDark,
    failed = StatusFailedDark,
    failedContainer = StatusFailedContainerDark,
    unknown = StatusUnknownDark,
    unknownContainer = StatusUnknownContainerDark
)

private val LightStatusColors = FodStatusColors(
    confirmed = StatusConfirmedLight,
    confirmedContainer = StatusConfirmedContainerLight,
    observed = StatusObservedLight,
    observedContainer = StatusObservedContainerLight,
    suspect = StatusSuspectLight,
    suspectContainer = StatusSuspectContainerLight,
    failed = StatusFailedLight,
    failedContainer = StatusFailedContainerLight,
    unknown = StatusUnknownLight,
    unknownContainer = StatusUnknownContainerLight
)

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp)
)

@Composable
fun FodDetectorTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val statusColors = if (darkTheme) DarkStatusColors else LightStatusColors

    CompositionLocalProvider(LocalFodStatusColors provides statusColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AppTypography,
            shapes = AppShapes,
            content = content
        )
    }
}
