@echo off
rem ATEBEAGLE - menu para subir o sistema, verificar a placa e abrir as telas.
rem A logica fica em scripts\launcher.py. Nao precisa rodar como administrador.
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title ATEBEAGLE

where py >/dev/null 2>nul
if %errorlevel%==0 (
    py -3 scripts\launcher.py %*
    goto :fim
)
where python >/dev/null 2>nul
if %errorlevel%==0 (
    python scripts\launcher.py %*
    goto :fim
)
echo [ERRO] Python nao encontrado.
echo O que fazer: instale o Python 3 (python.org), marcando "Add to PATH".
pause
exit /b 1

:fim
set "RC=%errorlevel%"
if not "%RC%"=="0" (
    echo.
    echo O menu terminou com erro %RC%. Os logs ficam em runs\launcher\.
    pause
)
endlocal & exit /b %RC%
