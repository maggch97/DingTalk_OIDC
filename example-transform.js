// Example JavaScript function to transform OIDC claims
// This function will be executed before signing the ID token
// You can modify claims, add new fields, or remove existing ones

function transform(claims) {
    // Example 1: Add custom groups/roles based on user email
    if (claims.email) {
        if (claims.email.endsWith('@admin.example.com')) {
            claims.groups = ['admin', 'users'];
            claims.role = 'admin';
        } else if (claims.email.endsWith('@example.com')) {
            claims.groups = ['users'];
            claims.role = 'user';
        } else {
            claims.groups = ['guest'];
            claims.role = 'guest';
        }
    }

    // Example 2: Add organization information
    claims.organization = 'MyCompany';
    
    // Example 3: Add preferred username from email
    if (claims.email) {
        claims.preferred_username = claims.email.split('@')[0];
    }

    // IMPORTANT: Always return the claims object
    return claims;
}
