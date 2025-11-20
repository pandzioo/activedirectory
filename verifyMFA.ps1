<#
.SYNOPSIS
    Skrypt do sprawdzania statusu MFA użytkowników w Microsoft 365 / Entra ID

.DESCRIPTION
    Skrypt automatycznie instaluje wymagane moduły Microsoft Graph,
    łączy się z Entra ID i generuje raport pokazujący status MFA
    dla wszystkich użytkowników w organizacji.

.NOTES
    Nazwa pliku: verifyMFA.ps1
    Autor: Automatycznie wygenerowany
    Wymagania: PowerShell 5.1 lub wyższy, uprawnienia administratora
#>

#Requires -Version 5.1

# Kolory dla lepszej czytelności
$ErrorActionPreference = "Stop"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Install-RequiredModules {
    Write-ColorOutput "`n=== Sprawdzanie i instalacja wymaganych modułów ===" -Color Cyan

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.SignIns"
    )

    foreach ($module in $requiredModules) {
        Write-ColorOutput "Sprawdzanie modułu: $module" -Color Yellow

        $installedModule = Get-Module -ListAvailable -Name $module

        if (-not $installedModule) {
            Write-ColorOutput "Instalowanie modułu: $module..." -Color Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-ColorOutput "✓ Moduł $module został zainstalowany pomyślnie" -Color Green
            }
            catch {
                Write-ColorOutput "✗ Błąd podczas instalacji modułu $module : $_" -Color Red
                throw
            }
        }
        else {
            Write-ColorOutput "✓ Moduł $module jest już zainstalowany" -Color Green
        }

        # Import modułu
        Import-Module $module -ErrorAction Stop
    }

    Write-ColorOutput "`n✓ Wszystkie wymagane moduły są gotowe`n" -Color Green
}

function Connect-ToEntraID {
    Write-ColorOutput "=== Łączenie z Entra ID (Azure AD) ===" -Color Cyan

    try {
        # Wymagane uprawnienia do odczytu użytkowników i informacji o MFA
        $scopes = @(
            "User.Read.All",
            "UserAuthenticationMethod.Read.All",
            "AuditLog.Read.All"
        )

        Write-ColorOutput "Logowanie do Microsoft Graph..." -Color Yellow
        Write-ColorOutput "Zostaniesz poproszony o zalogowanie się w przeglądarce." -Color Yellow

        Connect-MgGraph -Scopes $scopes -NoWelcome

        $context = Get-MgContext
        Write-ColorOutput "✓ Połączono pomyślnie" -Color Green
        Write-ColorOutput "  Tenant: $($context.TenantId)" -Color Gray
        Write-ColorOutput "  Konto: $($context.Account)`n" -Color Gray
    }
    catch {
        Write-ColorOutput "✗ Błąd podczas łączenia z Entra ID: $_" -Color Red
        throw
    }
}

function Get-MFAStatus {
    Write-ColorOutput "=== Pobieranie informacji o użytkownikach i statusie MFA ===" -Color Cyan

    try {
        # Pobierz wszystkich użytkowników
        Write-ColorOutput "Pobieranie listy użytkowników..." -Color Yellow
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, Mail

        Write-ColorOutput "Znaleziono $($users.Count) użytkowników. Sprawdzanie statusu MFA..." -Color Yellow

        $mfaReport = @()
        $counter = 0

        foreach ($user in $users) {
            $counter++
            Write-Progress -Activity "Sprawdzanie statusu MFA" -Status "Przetwarzanie $counter z $($users.Count)" -PercentComplete (($counter / $users.Count) * 100)

            try {
                # Pobierz metody uwierzytelniania dla użytkownika
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue

                # Sprawdź dostępne metody MFA
                $hasMFA = $false
                $mfaMethods = @()

                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties["@odata.type"]

                    switch ($methodType) {
                        "#microsoft.graph.phoneAuthenticationMethod" {
                            $hasMFA = $true
                            $mfaMethods += "Telefon"
                        }
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                            $hasMFA = $true
                            $mfaMethods += "Microsoft Authenticator"
                        }
                        "#microsoft.graph.fido2AuthenticationMethod" {
                            $hasMFA = $true
                            $mfaMethods += "FIDO2"
                        }
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                            $hasMFA = $true
                            $mfaMethods += "Windows Hello"
                        }
                        "#microsoft.graph.emailAuthenticationMethod" {
                            $mfaMethods += "Email (nie MFA)"
                        }
                        "#microsoft.graph.softwareOathAuthenticationMethod" {
                            $hasMFA = $true
                            $mfaMethods += "Software OATH"
                        }
                    }
                }

                $mfaStatus = if ($hasMFA) { "Włączone" } else { "Wyłączone" }
                $methodsList = if ($mfaMethods.Count -gt 0) { $mfaMethods -join ", " } else { "Brak" }

                $mfaReport += [PSCustomObject]@{
                    DisplayName       = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email             = $user.Mail
                    AccountEnabled    = $user.AccountEnabled
                    MFAStatus         = $mfaStatus
                    MFAMethods        = $methodsList
                }
            }
            catch {
                Write-ColorOutput "  Ostrzeżenie: Nie można pobrać danych MFA dla $($user.UserPrincipalName)" -Color Yellow

                $mfaReport += [PSCustomObject]@{
                    DisplayName       = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email             = $user.Mail
                    AccountEnabled    = $user.AccountEnabled
                    MFAStatus         = "Błąd odczytu"
                    MFAMethods        = "N/A"
                }
            }
        }

        Write-Progress -Activity "Sprawdzanie statusu MFA" -Completed

        return $mfaReport
    }
    catch {
        Write-ColorOutput "✗ Błąd podczas pobierania informacji o MFA: $_" -Color Red
        throw
    }
}

function Show-MFAReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Report
    )

    Write-ColorOutput "`n=== RAPORT STATUSU MFA ===" -Color Cyan
    Write-ColorOutput "Data wygenerowania: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -Color Gray

    # Statystyki
    $totalUsers = $Report.Count
    $mfaEnabled = ($Report | Where-Object { $_.MFAStatus -eq "Włączone" }).Count
    $mfaDisabled = ($Report | Where-Object { $_.MFAStatus -eq "Wyłączone" }).Count
    $mfaError = ($Report | Where-Object { $_.MFAStatus -eq "Błąd odczytu" }).Count
    $activeUsers = ($Report | Where-Object { $_.AccountEnabled -eq $true }).Count

    Write-ColorOutput "=== STATYSTYKI ===" -Color Yellow
    Write-ColorOutput "Łączna liczba użytkowników: $totalUsers" -Color White
    Write-ColorOutput "Aktywne konta: $activeUsers" -Color White
    Write-ColorOutput "MFA włączone: $mfaEnabled ($([math]::Round(($mfaEnabled/$totalUsers)*100, 2))%)" -Color Green
    Write-ColorOutput "MFA wyłączone: $mfaDisabled ($([math]::Round(($mfaDisabled/$totalUsers)*100, 2))%)" -Color Red
    if ($mfaError -gt 0) {
        Write-ColorOutput "Błędy odczytu: $mfaError" -Color Yellow
    }

    # Wyświetl szczegółowy raport
    Write-ColorOutput "`n=== UŻYTKOWNICY Z WYŁĄCZONYM MFA ===" -Color Red
    $disabledMFA = $Report | Where-Object { $_.MFAStatus -eq "Wyłączone" -and $_.AccountEnabled -eq $true }

    if ($disabledMFA.Count -gt 0) {
        $disabledMFA | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, Email, AccountEnabled
    }
    else {
        Write-ColorOutput "✓ Wszyscy aktywni użytkownicy mają włączone MFA!" -Color Green
    }

    Write-ColorOutput "`n=== UŻYTKOWNICY Z WŁĄCZONYM MFA ===" -Color Green
    $enabledMFA = $Report | Where-Object { $_.MFAStatus -eq "Włączone" }

    if ($enabledMFA.Count -gt 0) {
        $enabledMFA | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, MFAMethods
    }
    else {
        Write-ColorOutput "Brak użytkowników z włączonym MFA" -Color Yellow
    }

    # Zapisz raport do pliku
    $reportPath = "MFA_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Report | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-ColorOutput "`n✓ Raport zapisano do pliku: $reportPath" -Color Green

    # Pełny raport w konsoli
    Write-ColorOutput "`n=== PEŁNY RAPORT (WSZYSCY UŻYTKOWNICY) ===" -Color Cyan
    $Report | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, AccountEnabled, MFAStatus, MFAMethods
}

# ============================================
# GŁÓWNA FUNKCJA SKRYPTU
# ============================================

function Main {
    Clear-Host

    Write-ColorOutput @"
╔════════════════════════════════════════════════════════════╗
║         SKRYPT WERYFIKACJI MFA - ENTRA ID / M365           ║
╚════════════════════════════════════════════════════════════╝
"@ -Color Cyan

    try {
        # Krok 1: Instalacja modułów
        Install-RequiredModules

        # Krok 2: Połączenie z Entra ID
        Connect-ToEntraID

        # Krok 3: Pobranie statusu MFA
        $mfaReport = Get-MFAStatus

        # Krok 4: Wyświetlenie raportu
        Show-MFAReport -Report $mfaReport

        Write-ColorOutput "`n✓ Skrypt zakończony pomyślnie!" -Color Green

        # Rozłącz się z Microsoft Graph
        Write-ColorOutput "`nRozłączanie z Microsoft Graph..." -Color Yellow
        Disconnect-MgGraph | Out-Null
        Write-ColorOutput "✓ Rozłączono`n" -Color Green
    }
    catch {
        Write-ColorOutput "`n✗ BŁĄD: $_" -Color Red
        Write-ColorOutput "Szczegóły: $($_.Exception.Message)" -Color Red

        # Spróbuj rozłączyć się w przypadku błędu
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }

        exit 1
    }
}

# Uruchom skrypt
Main
