# param([Mandatory][Guid]$Guid)
# -Join ($GUID.ToByteArray() | % { ($_ -band 15).ToString('X') + ($_ -shr 4).ToString('X') })

param(
    [Parameter(Mandatory)]
    [Guid]$Guid
)

-Join ($GUID.ToByteArray() | ForEach-Object {
    ($_ -band 15).ToString('X') + ($_ -shr 4).ToString('X') 
})