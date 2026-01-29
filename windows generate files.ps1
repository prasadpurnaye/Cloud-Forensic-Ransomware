# PowerShell Script to Generate Nested Folder Structure
# Creates 3 levels of folders and files in Documents, Downloads, Music, and Videos

# Function to create nested structure
function Create-NestedStructure {
    param (
        [string]$BasePath,
        [string]$BaseName,
        [int]$CurrentLevel,
        [int]$MaxLevel
    )
    
    if ($CurrentLevel -gt $MaxLevel) {
        return
    }
    
    # Create 2 folders at current level
    for ($i = 1; $i -le 2; $i++) {
        $folderName = "${BaseName}_Level${CurrentLevel}_Folder${i}"
        $folderPath = Join-Path -Path $BasePath -ChildPath $folderName
        
        # Create the folder
        New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $folderPath" -ForegroundColor Green
        
        # Create 2 text files in this folder
        for ($j = 1; $j -le 2; $j++) {
            $fileName = "${BaseName}_Level${CurrentLevel}_Folder${i}_textFile${j}.txt"
            $filePath = Join-Path -Path $folderPath -ChildPath $fileName
            
            # Create the file with some content
            $content = @"
This is a test file created by PowerShell script.
File: $fileName
Location: $folderPath
Parent Folder: $BaseName
Level: $CurrentLevel
Created: $(Get-Date)
"@
            Set-Content -Path $filePath -Value $content
            Write-Host "  Created file: $fileName" -ForegroundColor Cyan
        }
        
        # Recursively create structure in this folder (next level)
        Create-NestedStructure -BasePath $folderPath -BaseName $BaseName -CurrentLevel ($CurrentLevel + 1) -MaxLevel $MaxLevel
    }
}

# Main script execution
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "  PowerShell Nested Structure Generator" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host ""

# Get user's home directory
$homeDir = [Environment]::GetFolderPath("UserProfile")

# Define target directories
$targetDirs = @{
    "Documents" = Join-Path -Path $homeDir -ChildPath "Documents"
    "Downloads" = Join-Path -Path $homeDir -ChildPath "Downloads"
    "Music"     = Join-Path -Path $homeDir -ChildPath "Music"
    "Videos"    = Join-Path -Path $homeDir -ChildPath "Videos"
}

# Number of levels to create
$maxLevels = 3

Write-Host "Starting structure generation..." -ForegroundColor Yellow
Write-Host "Home Directory: $homeDir" -ForegroundColor White
Write-Host "Levels to create: $maxLevels" -ForegroundColor White
Write-Host ""

# Create structure in each target directory
foreach ($dirName in $targetDirs.Keys) {
    $dirPath = $targetDirs[$dirName]
    
    Write-Host "=====================================================================" -ForegroundColor Magenta
    Write-Host "Processing: $dirName" -ForegroundColor Magenta
    Write-Host "Path: $dirPath" -ForegroundColor Magenta
    Write-Host "=====================================================================" -ForegroundColor Magenta
    
    # Check if directory exists
    if (Test-Path -Path $dirPath) {
        # Create nested structure starting from level 1
        Create-NestedStructure -BasePath $dirPath -BaseName $dirName -CurrentLevel 1 -MaxLevel $maxLevels
        Write-Host ""
    } else {
        Write-Host "Warning: Directory not found - $dirPath" -ForegroundColor Red
        Write-Host ""
    }
}

Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "Structure Generation Complete!" -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host ""

# Display summary
Write-Host "Summary:" -ForegroundColor White
Write-Host "--------" -ForegroundColor White
Write-Host "Directories processed: $($targetDirs.Count)" -ForegroundColor White
Write-Host "Levels created: $maxLevels" -ForegroundColor White
Write-Host "Folders per level: 2" -ForegroundColor White
Write-Host "Files per folder: 2" -ForegroundColor White
Write-Host ""

# Calculate total items created
$foldersPerLevel = 2
$totalFolders = 0
$totalFiles = 0

for ($level = 1; $level -le $maxLevels; $level++) {
    $foldersAtLevel = [Math]::Pow($foldersPerLevel, $level)
    $totalFolders += $foldersAtLevel
    $totalFiles += $foldersAtLevel * 2  # 2 files per folder
}

$totalFolders *= $targetDirs.Count  # Multiply by number of base directories
$totalFiles *= $targetDirs.Count

Write-Host "Total folders created: $totalFolders" -ForegroundColor Green
Write-Host "Total files created: $totalFiles" -ForegroundColor Green
Write-Host ""
Write-Host "Done! You can now run the Python traversal script to see all files." -ForegroundColor Yellow
