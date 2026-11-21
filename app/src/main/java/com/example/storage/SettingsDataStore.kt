package com.example.storage

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.i18n.AppLanguage
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "fod_detector_settings")

data class UserSettings(
    val language: AppLanguage = AppLanguage.FR,
    val rootEnabled: Boolean = false,
    val personalGeminiApiKey: String = ""
)

class SettingsDataStore(private val context: Context) {

    private object Keys {
        val LANGUAGE = stringPreferencesKey("app_language")
        val ROOT_ENABLED = booleanPreferencesKey("root_enabled")
        val PERSONAL_GEMINI_API_KEY = stringPreferencesKey("personal_gemini_api_key")
    }

    val settingsFlow: Flow<UserSettings> = context.dataStore.data.map { prefs ->
        val langCode = prefs[Keys.LANGUAGE] ?: AppLanguage.FR.code
        val lang = AppLanguage.entries.firstOrNull { it.code == langCode } ?: AppLanguage.FR
        val root = prefs[Keys.ROOT_ENABLED] ?: false
        val apiKey = prefs[Keys.PERSONAL_GEMINI_API_KEY].orEmpty()
        UserSettings(
            language = lang,
            rootEnabled = root,
            personalGeminiApiKey = apiKey
        )
    }

    suspend fun setLanguage(language: AppLanguage) {
        context.dataStore.edit { prefs ->
            prefs[Keys.LANGUAGE] = language.code
        }
    }

    suspend fun setRootEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ROOT_ENABLED] = enabled
        }
    }

    suspend fun setPersonalGeminiApiKey(apiKey: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.PERSONAL_GEMINI_API_KEY] = apiKey.trim()
        }
    }
}
