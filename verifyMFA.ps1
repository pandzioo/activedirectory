<#
.SYNOPSIS
    Skrypt do sprawdzania statusu MFA uzytkownikow w Microsoft 365 / Entra ID

.DESCRIPTION
    Skrypt automatycznie instaluje wymagane moduly Microsoft Graph,
    laczy sie z Entra ID i generuje raport pokazujacy status MFA
    dla wszystkich uzytkownikow w organizacji.

.NOTES
    Nazwa pliku: verifyMFA.ps1
    Autor: Automatycznie wygenerowany
    Wymagania: PowerShell 5.1 lub wyzszy, uprawnienia administratora
#>

#Requires -Version 5.1

# Kolory dla lepszej czytelnoci
$ErrorActionPreference = "Stop"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Install-RequiredModules {
    Write-ColorOutput "`n=== Sprawdzanie i instalacja wymaganych modulow ===" -Color Cyan

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.SignIns"
    )

    foreach ($module in $requiredModules) {
        Write-ColorOutput "Sprawdzanie modulu: $module" -Color Yellow

        $installedModule = Get-Module -ListAvailable -Name $module

        if (-not $installedModule) {
            Write-ColorOutput "Instalowanie modulu: $module..." -Color Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-ColorOutput "[OK] Modul $module zostal zainstalowany pomyslnie" -Color Green
            }
            catch {
                Write-ColorOutput "[BLAD] Blad podczas instalacji modulu ${module}: $_" -Color Red
                throw
            }
        }
        else {
            Write-ColorOutput "[OK] Modul $module jest juz zainstalowany" -Color Green
        }

        # Import modulu
        Import-Module $module -ErrorAction Stop
    }

    Write-ColorOutput "`n[OK] Wszystkie wymagane moduly sa gotowe`n" -Color Green
}

function Connect-ToEntraID {
    Write-ColorOutput "=== Laczenie z Entra ID (Azure AD) ===" -Color Cyan

    try {
        # Wymagane uprawnienia do odczytu uzytkownikow i informacji o MFA
        $scopes = @(
            "User.Read.All",
            "UserAuthenticationMethod.Read.All",
            "AuditLog.Read.All"
        )

        Write-ColorOutput "Logowanie do Microsoft Graph..." -Color Yellow
        Write-ColorOutput "Zostaniesz poproszony o zalogowanie sie w przegladarce." -Color Yellow

        Connect-MgGraph -Scopes $scopes -NoWelcome

        $context = Get-MgContext
        Write-ColorOutput "[OK] Polaczono pomyslnie" -Color Green
        Write-ColorOutput "  Tenant: $($context.TenantId)" -Color Gray
        Write-ColorOutput "  Konto: $($context.Account)`n" -Color Gray
    }
    catch {
        Write-ColorOutput "[BLAD] Blad podczas laczenia z Entra ID: $_" -Color Red
        throw
    }
}

function Get-MFAStatus {
    Write-ColorOutput "=== Pobieranie informacji o uzytkownikach i statusie MFA ===" -Color Cyan

    try {
        # Pobierz wszystkich uzytkownikow
        Write-ColorOutput "Pobieranie listy uzytkownikow..." -Color Yellow
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, Mail

        Write-ColorOutput "Znaleziono $($users.Count) uzytkownikow. Sprawdzanie statusu MFA..." -Color Yellow

        $mfaReport = @()
        $counter = 0

        foreach ($user in $users) {
            $counter++
            Write-Progress -Activity "Sprawdzanie statusu MFA" -Status "Przetwarzanie $counter z $($users.Count)" -PercentComplete (($counter / $users.Count) * 100)

            try {
                # Pobierz metody uwierzytelniania dla uzytkownika
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue

                # Sprawdz dostepne metody MFA
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

                $mfaStatus = if ($hasMFA) { "Wlaczone" } else { "Wylaczone" }
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
                Write-ColorOutput "  Ostrzezenie: Nie mozna pobrac danych MFA dla $($user.UserPrincipalName)" -Color Yellow

                $mfaReport += [PSCustomObject]@{
                    DisplayName       = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email             = $user.Mail
                    AccountEnabled    = $user.AccountEnabled
                    MFAStatus         = "Blad odczytu"
                    MFAMethods        = "N/A"
                }
            }
        }

        Write-Progress -Activity "Sprawdzanie statusu MFA" -Completed

        return $mfaReport
    }
    catch {
        Write-ColorOutput "[BLAD] Blad podczas pobierania informacji o MFA: $_" -Color Red
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
    $mfaEnabled = ($Report | Where-Object { $_.MFAStatus -eq "Wlaczone" }).Count
    $mfaDisabled = ($Report | Where-Object { $_.MFAStatus -eq "Wylaczone" }).Count
    $mfaError = ($Report | Where-Object { $_.MFAStatus -eq "Blad odczytu" }).Count
    $activeUsers = ($Report | Where-Object { $_.AccountEnabled -eq $true }).Count

    Write-ColorOutput "=== STATYSTYKI ===" -Color Yellow
    Write-ColorOutput "Laczna liczba uzytkownikow: $totalUsers" -Color White
    Write-ColorOutput "Aktywne konta: $activeUsers" -Color White
    Write-ColorOutput "MFA wlaczone: $mfaEnabled ($([math]::Round(($mfaEnabled/$totalUsers)*100, 2))%)" -Color Green
    Write-ColorOutput "MFA wylaczone: $mfaDisabled ($([math]::Round(($mfaDisabled/$totalUsers)*100, 2))%)" -Color Red
    if ($mfaError -gt 0) {
        Write-ColorOutput "Bledy odczytu: $mfaError" -Color Yellow
    }

    # Wyswietl szczegolowy raport
    Write-ColorOutput "`n=== UZYTKOWNICY Z WYLACZONYM MFA ===" -Color Red
    $disabledMFA = $Report | Where-Object { $_.MFAStatus -eq "Wylaczone" -and $_.AccountEnabled -eq $true }

    if ($disabledMFA.Count -gt 0) {
        $disabledMFA | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, Email, AccountEnabled
    }
    else {
        Write-ColorOutput "[OK] Wszyscy aktywni uzytkownicy maja wlaczone MFA!" -Color Green
    }

    Write-ColorOutput "`n=== UZYTKOWNICY Z WLACZONYM MFA ===" -Color Green
    $enabledMFA = $Report | Where-Object { $_.MFAStatus -eq "Wlaczone" }

    if ($enabledMFA.Count -gt 0) {
        $enabledMFA | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, MFAMethods
    }
    else {
        Write-ColorOutput "Brak uzytkownikow z wlaczonym MFA" -Color Yellow
    }

    # Zapisz raport do pliku
    $reportPath = "MFA_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Report | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-ColorOutput "`n[OK] Raport zapisano do pliku: $reportPath" -Color Green

    # Pelny raport w konsoli
    Write-ColorOutput "`n=== PELNY RAPORT (WSZYSCY UZYTKOWNICY) ===" -Color Cyan
    $Report | Format-Table -AutoSize -Property DisplayName, UserPrincipalName, AccountEnabled, MFAStatus, MFAMethods
}

# ============================================
# GLOWNA FUNKCJA SKRYPTU
# ============================================

function Main {
    Clear-Host

    Write-ColorOutput @"
================================================================
         SKRYPT WERYFIKACJI MFA - ENTRA ID / M365
================================================================
"@ -Color Cyan

    try {
        # Krok 1: Instalacja modulow
        Install-RequiredModules

        # Krok 2: Polaczenie z Entra ID
        Connect-ToEntraID

        # Krok 3: Pobranie statusu MFA
        $mfaReport = Get-MFAStatus

        # Krok 4: Wyswietlenie raportu
        Show-MFAReport -Report $mfaReport

        Write-ColorOutput "`n[OK] Skrypt zakonczony pomyslnie!" -Color Green

        # Rozlacz sie z Microsoft Graph
        Write-ColorOutput "`nRozlaczanie z Microsoft Graph..." -Color Yellow
        Disconnect-MgGraph | Out-Null
        Write-ColorOutput "[OK] Rozlaczono`n" -Color Green
    }
    catch {
        Write-ColorOutput "`n[BLAD] BLAD: $_" -Color Red
        Write-ColorOutput "Szczegoly: $($_.Exception.Message)" -Color Red

        # Sprobuj rozlaczyc sie w przypadku bledu
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }

        exit 1
    }
}

# Uruchom skrypt
Main
