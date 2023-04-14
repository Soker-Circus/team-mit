
const USER_ROLE_ADMIN          = 0;
const USER_ROLE_EMPLOYER       = 1;
const USER_ROLE_VOLUNTEER      = 2;
const USER_ROLE_REGIONAL_ADMIN = 4;

const FPR_API_KEY              = 'kaipuLla401326';

// Shortcuts / Alis
colog = console.log;


/*

https://www.sohamkamani.com/blog/2017/08/21/enums-in-javascript/

*/
/* We don't need this
const error_codes_enum = {
    INVALID_CREDENTIALS: [4008, "Invalid cred"],
    SUCCESS: 0
}
*/

const error_codes = {

    0       : "Success",

    404     : "API Not Found",
    405     : "Method Not Allowed",
    500     : "Internal Server Error",

    1001    : "Will be implemented in Future",
    4001    : "Login Failed",
    4002    : "Super Admin Required To Perform This Action",
    4003    : "Employer Required To Perform This Action",
    4004    : "Insufficient Tact Coins",
    4005    : "Email Already Exists",
    4006    : "User Does Not Exist",
    4007    : "User Inactive",
    4008    : "Invalid Credentials",
    4009    : "Not Registered As Employer",
    4010    : "Not Registered As Volunteer",
    4011    : "API Key Required",
    4012    : "API Key Not Matched",
    4013    : "Login Required",
    4014    : "Invalid Session",
    4015    : "Broken Session Id",
    4016    : "Session Expired",
    4017    : "IP Mismatch",
    4018    : "Userid Mismatch",
    4019    : "Param Missing",
    4020    : "Unknown Error",
    4021    : "Confirmation Code Expired",
    4022    : "Broken Confirmation Code",
    4023    : "Not Authorized To Perform This Operation",
    4024    : "Item Does Not Exist",
    4025    : "Duplicate Entry",
    4026    : "Item Not Inserted",
    4027    : "Item Not Updated",
    4028    : "Item Missing From Request Body",
    4029    : "API Key Cap Reached",
    4030    : "Not Registered As Super Admin",
    4030    : "Not Registered As Super Admin",

    4008    : "Invalid Creds" 
}