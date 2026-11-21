package com.example.viewmodel

import android.app.Application
import android.os.Build
import android.os.Environment
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.engine.GeminiFodAiAnalyzer
import com.example.engine.ShellExecutor
import com.example.i18n.AppLanguage
import com.example.storage.SettingsDataStore
import com.example.storage.UserSettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class RootTestState(
    val testing: Boolean = false,
    val granted: Boolean? = null,
    val detail: String = ""
)

data class AiTestState(
    val testing: Boolean = false,
    val success: Boolean? = null,
    val providerName: String = "",
    val detail: String = ""
)

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val store = SettingsDataStore(application)
    private val aiAnalyzer = GeminiFodAiAnalyzer(application)

    val settings: StateFlow<UserSettings> = store.settingsFlow.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = UserSettings()
    )

    private val _rootTestState = MutableStateFlow(RootTestState())
    val rootTestState: StateFlow<RootTestState> = _rootTestState.asStateFlow()

    private val _aiTestState = MutableStateFlow(AiTestState())
    val aiTestState: StateFlow<AiTestState> = _aiTestState.asStateFlow()

    private val _allFilesGranted = MutableStateFlow(checkAllFilesPermission())
    val allFilesGranted: StateFlow<Boolean> = _allFilesGranted.asStateFlow()

    fun setLanguage(language: AppLanguage) {
        viewModelScope.launch { store.setLanguage(language) }
    }

    fun setPersonalGeminiApiKey(key: String) {
        viewModelScope.launch {
            store.setPersonalGeminiApiKey(key)
            _aiTestState.value = AiTestState()
        }
    }

    fun testAiConnection(keyOverride: String? = null, language: AppLanguage) {
        viewModelScope.launch {
            _aiTestState.value = AiTestState(testing = true)
            val result = aiAnalyzer.testAiConnection(apiKeyOverride = keyOverride, language = language)
            _aiTestState.value = AiTestState(
                testing = false,
                success = result.success,
                providerName = result.providerName,
                detail = result.detail
            )
        }
    }

    fun setRootEnabled(enabled: Boolean) {
        viewModelScope.launch {
            store.setRootEnabled(enabled)
            if (enabled) {
                testRoot()
            } else {
                _rootTestState.value = RootTestState()
            }
        }
    }

    fun testRoot() {
        viewModelScope.launch {
            _rootTestState.value = RootTestState(testing = true)
            val (ok, detail) = ShellExecutor.testRootAccess()
            _rootTestState.value = RootTestState(testing = false, granted = ok, detail = detail)
        }
    }

    fun refreshStoragePermission() {
        _allFilesGranted.value = checkAllFilesPermission()
    }

    private fun checkAllFilesPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }
    }
}
