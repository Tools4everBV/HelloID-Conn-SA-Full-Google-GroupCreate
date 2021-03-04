#region Support Functions
function Get-GoogleAccessToken() {
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"
        
    $refreshTokenParams = @{
            client_id=$GoogleClientId;
            client_secret=$GoogleClientSecret;
            redirect_uri=$GoogleRedirectUri;
            refresh_token=$GoogleRefreshToken;
            grant_type="refresh_token"; # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token
            
    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $($accesstoken)";
        'Content-Type' = "application/json; charset=utf-8";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

#region Execute
try {
    $GroupParams = @{
        name           = $name
        description    = $description
        email          = $email

    }
    
    #Add the authorization header to the request
	$authorization = Get-GoogleAccessToken
    
    $splat = @{
			Uri = "https://www.googleapis.com/admin/directory/v1/groups"
			Body = ($GroupParams | ConvertTo-Json)
			Method = 'POST'
			Headers = $authorization
		}
    
	$response = Invoke-RestMethod @splat 
    
    Hid-Write-Status -Message "Google group [$name] created successfully" -Event Success
    HID-Write-Summary -Message "Google group [$name] created successfully" -Event Success
} catch {
    HID-Write-Status -Message "Error creating Google group [$name]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Error creating Google group [$name]" -Event Failed
}
#endregion Execute
