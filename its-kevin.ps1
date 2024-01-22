# Load the System.Drawing assembly
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# Script Variables
$tmp = "c:\temp\"
$imagePath = 'C:\temp\Kevin.png'
$url = "https://advancestuff.hostedrmm.com/labtech/transfer/CCUpload/kevin.png"
# Create temp directory
if(!(Test-Path $tmp)) {
    new-item -Path "c:\temp\" -ItemType Directory -Force
}

# Path to the image
Invoke-WebRequest -uri $url -OutFile $imagePath


# Check if the image exists
if (!(Test-Path -Path $imagePath)) {
    Write-Host "Image not found at $imagePath. Please check the file path."
} else {
    try {
        # Load the image
        $image = [System.Drawing.Image]::FromFile($imagePath)

        # Create a form to display the image
        $form = New-Object Windows.Forms.Form
        $form.Text = "Image Display"
        $form.Width = $image.Width
        $form.Height = $image.Height
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None

        # Create a PictureBox to hold the image
        $pictureBox = New-Object Windows.Forms.PictureBox
        $pictureBox.Width = $image.Width
        $pictureBox.Height = $image.Height
        $pictureBox.Image = $image

        # Add the PictureBox to the form
        $form.Controls.Add($pictureBox)

        # Center the form on the screen
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

        # Display the form for 10 seconds then close
        $form.Show()
        Start-Sleep -Seconds 10
        $form.Close()
    } catch {
        Write-Host "Error loading image: $_"
    }
}