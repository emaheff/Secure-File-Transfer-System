#include "Constants.h"
#include <string> 

/**
 * @namespace Constants
 * @brief Provides definitions for file paths used in the client-server communication.
 *
 * The Constants.cpp file defines the actual file paths for files like transfer.info, me.info, and priv.key.
 */
namespace Constants {
    std::string TRANSFER_FILE = "transfer.info"; 
    std::string ME_FILE = "me.info"; 
    std::string PRIV_FILE = "priv.key"; 
}