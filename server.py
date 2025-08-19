import json
import logging
import os
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Load environment variables from .env file in the current directory
load_dotenv()

# Configure logging to show INFO level messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RansomwareLiveAPI:
    """
    Client for interacting with the Ransomware.live Pro API.
    
    This class provides methods to fetch data about ransomware attacks,
    including information about threat groups, victims, sectors, and statistics.
    """
    
    # Base URL for all API endpoints
    BASE_URL = "https://api-pro.ransomware.live"
    
    def __init__(self, api_key: str):
        """
        Initialize the API client with authentication.
        
        Args:
            api_key: The API key for authentication with Ransomware.live Pro API
        
        Raises:
            ValueError: If no API key is provided
        """
        if not api_key:
            raise ValueError("API key is required")
        
        # Set up headers with API key for authentication
        self.headers = {
            "X-API-KEY": api_key,
            "Content-Type": "application/json"
        }
        
        # Create an HTTP client with timeout and default headers
        self.client = httpx.Client(
            timeout=30.0,  # 30 second timeout for requests
            headers=self.headers
        )
    
    async def list_sectors(self) -> Dict[str, Any]:
        """
        Retrieve a list of all sectors/industries tracked by the API.
        
        Returns:
            Dict containing sector information
        """
        response = self.client.get(f"{self.BASE_URL}/listsectors")
        response.raise_for_status()  # Raise exception for HTTP errors
        return response.json()
    
    async def list_groups(self) -> Dict[str, Any]:
        """
        Retrieve a list of all known ransomware groups.
        
        Returns:
            Dict containing information about all ransomware groups
        """
        response = self.client.get(f"{self.BASE_URL}/listgroups")
        response.raise_for_status()
        return response.json()
    
    async def get_group_info(self, group_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific ransomware group.
        
        Args:
            group_name: The name/identifier of the ransomware group
        
        Returns:
            Dict containing detailed group information including tactics, victims, etc.
        """
        response = self.client.get(f"{self.BASE_URL}/groups/{group_name}")
        response.raise_for_status()
        return response.json()
    
    async def list_victims(self, group: str = None, sector: str = None, 
                        country: str = None, year: str = None, 
                        month: str = None) -> Dict[str, Any]:
        """
        List ransomware victims with filters.
        At least one filter parameter should be provided.
        
        Args:
            group: Optional filter by ransomware group name
            sector: Optional filter by sector/industry
            country: Optional filter by country
            year: Optional filter by 4-digit year
            month: Optional filter by 2-digit month
        
        Returns:
            Dict containing victim information matching the filters
        
        Raises:
            ValueError: If no filter parameters are provided
        """
        params = {}
        
        # Add filter parameters if provided
        if group:
            params["group"] = group
        if sector:
            params["sector"] = sector
        if country:
            params["country"] = country
        if year:
            params["year"] = year
        if month:
            params["month"] = month
        
        # Ensure at least one filter is provided
        if not params:
            raise ValueError("At least one filter parameter is required (group, sector, country, year, or month)")
        
        response = self.client.get(f"{self.BASE_URL}/victims", params=params)
        response.raise_for_status()
        return response.json()
        
    async def get_victim_info(self, victim_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific ransomware victim.
        
        Args:
            victim_id: Unique identifier of the victim
        
        Returns:
            Dict containing detailed victim information including attack details
        """
        response = self.client.get(f"{self.BASE_URL}/victim/{victim_id}")
        response.raise_for_status()
        return response.json()
    
    async def search_victims(self, query: str, group_name: str = None, 
                           sector_name: str = None, country: str = None) -> Dict[str, Any]:
        """
        Search for victims using various criteria.
        
        Args:
            query: Search term (can be victim name, domain, or other identifiers)
            group_name: Optional filter by ransomware group name
            sector_name: Optional filter by sector/industry
            country: Optional filter by country
        
        Returns:
            Dict containing search results matching the query and filters
        """
        params = {"q": query}
        # Add optional parameters if provided
        if group_name:
            params["group"] = group_name
        if sector_name:
            params["sector"] = sector_name
        if country:
            params["country"] = country
            
        response = self.client.get(f"{self.BASE_URL}/victims/search", params=params)
        response.raise_for_status()
        return response.json()
    
    async def get_recent_victims(self, order: str = "discovered") -> Dict[str, Any]:
        """
        Get recently reported victims.
        
        Args:
            order: Sort order - "discovered" for recently discovered or "published" for recently published
        
        Returns:
            Dict containing recent victim information
        """
        params = {"order": order}
        response = self.client.get(f"{self.BASE_URL}/victims/recent", params=params)
        response.raise_for_status()
        return response.json()
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get general ransomware statistics.
        
        Returns:
            Dict containing overall statistics including attack counts, trends, etc.
        """
        response = self.client.get(f"{self.BASE_URL}/stats")
        response.raise_for_status()
        return response.json()
    
    async def get_ransomnotes(self) -> Dict[str, Any]:
        """
        Get a list of all available ransom notes.
        
        Returns:
            Dict containing information about ransom notes from various groups
        """
        response = self.client.get(f"{self.BASE_URL}/ransomnotes")
        response.raise_for_status()
        return response.json()
    
    async def get_ransomnotes_by_group(self, group_name: str) -> Dict[str, Any]:
        """
        Get ransom notes from a specific ransomware group.
        
        Args:
            group_name: Name of the ransomware group
        
        Returns:
            Dict containing ransom notes from the specified group
        """
        response = self.client.get(f"{self.BASE_URL}/ransomnotes/{group_name}")
        response.raise_for_status()
        return response.json()

    async def get_ransomnote_content(self, group_name: str, note_name: str) -> Dict[str, Any]:
        """
        Get the content of a specific ransom note.
        
        Args:
            group_name: Name of the ransomware group
            note_name: Name/identifier of the specific ransom note
        
        Returns:
            Dict containing the full content of the specified ransom note
        """
        response = self.client.get(f"{self.BASE_URL}/ransomnotes/{group_name}/{note_name}")
        response.raise_for_status()
        return response.json()
    
    def __del__(self):
        """
        Cleanup method to properly close the HTTP client when the object is destroyed.
        This prevents resource leaks.
        """
        if hasattr(self, 'client'):
            self.client.close()

# Initialize the MCP (Model Context Protocol) server with a descriptive name
app = Server("ransomware-live-mcp")

# Retrieve API key from environment variable
# This keeps sensitive credentials out of the code
API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY")
if not API_KEY:
    logger.error("RANSOMWARE_LIVE_API_KEY environment variable not set")
    raise ValueError("Please set RANSOMWARE_LIVE_API_KEY environment variable")

# Create a global instance of the API client to be used by all tool handlers
api_client = RansomwareLiveAPI(API_KEY)

@app.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """
    Define and return the list of available tools that can be called through MCP.
    
    Each tool definition includes:
    - name: Unique identifier for the tool
    - description: Human-readable description of what the tool does
    - inputSchema: JSON Schema defining the expected input parameters
    
    Returns:
        List of Tool definitions that clients can discover and use
    """
    return [
        types.Tool(
            name="list_sectors",
            description="Get list of all sectors/industries tracked",
            inputSchema={
                "type": "object",
                "properties": {}  # No parameters required
            }
        ),
        types.Tool(
            name="list_groups",
            description="Get list of all ransomware groups",
            inputSchema={
                "type": "object",
                "properties": {}  # No parameters required
            }
        ),
        types.Tool(
            name="get_group_info",
            description="Get detailed information about a specific ransomware group",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_name": {
                        "type": "string",
                        "description": "Name of the ransomware group (e.g., 'lockbit3', 'alphv')"
                    }
                },
                "required": ["group_name"]  # This parameter is mandatory
            }
        ),
        types.Tool(
            name="list_victims",
            description="List ransomware victims with filters (at least one filter required)",
            inputSchema={
                "type": "object",
                "properties": {
                    "group": {
                        "type": "string",
                        "description": "Filter by ransomware group name (e.g., lockbit)"
                    },
                    "sector": {
                        "type": "string",
                        "description": "Filter by victim sector (e.g., healthcare)"
                    },
                    "country": {
                        "type": "string",
                        "description": "Filter by 2-letter country code (e.g., US, FR)"
                    },
                    "year": {
                        "type": "string",
                        "description": "Filter by 4-digit year (e.g., '2024')",
                        "pattern": "^\\d{4}$"
                    },
                    "month": {
                        "type": "string",
                        "description": "Filter by 2-digit month (e.g., '01' for January)",
                        "pattern": "^(0[1-9]|1[0-2])$"
                    }
                },
                "anyOf": [
                    {"required": ["group"]},
                    {"required": ["sector"]},
                    {"required": ["country"]},
                    {"required": ["year"]},
                    {"required": ["month"]}
                ]
            }
        ),
        types.Tool(
            name="get_victim_info",
            description="Get detailed information about a specific victim",
            inputSchema={
                "type": "object",
                "properties": {
                    "victim_id": {
                        "type": "string",
                        "description": "ID of the victim"
                    }
                },
                "required": ["victim_id"]
            }
        ),
        types.Tool(
            name="search_victims",
            description="Search for victims by name, domain, or other criteria with optional filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query for victim name, domain, etc."
                    },
                    "group_name": {
                        "type": "string",
                        "description": "Optional: Filter by ransomware group name"
                    },
                    "sector_name": {
                        "type": "string",
                        "description": "Optional: Filter by sector/industry"
                    },
                    "country": {
                        "type": "string",
                        "description": "Optional: Filter by country"
                    }
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="get_recent_victims",
            description="Get recently reported victims",
            inputSchema={
                "type": "object",
                "properties": {
                    "order": {
                        "type": "string",
                        "description": "Sort order: 'discovered' or 'published' (default: 'discovered')",
                        "enum": ["discovered", "published"],
                        "default": "discovered"
                    }
                }
            }
        ),
        types.Tool(
            name="get_stats",
            description="Get general ransomware statistics",
            inputSchema={
                "type": "object",
                "properties": {}  # No parameters required
            }
        ),
        types.Tool(
            name="get_ransomnotes",
            description="Get list of all available ransom notes",
            inputSchema={
                "type": "object",
                "properties": {}  # No parameters required
            }
        ),
        types.Tool(
            name="get_ransomnotes_by_group",
            description="Get ransom notes from a specific ransomware group",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_name": {
                        "type": "string",
                        "description": "Name of the ransomware group"
                    }
                },
                "required": ["group_name"]
            }
        ),
        types.Tool(
            name="get_ransomnote_content",
            description="Get the content of a specific ransom note",
            inputSchema={
                "type": "object",
                "properties": {
                    "group_name": {
                        "type": "string",
                        "description": "Name of the ransomware group"
                    },
                    "note_name": {
                        "type": "string",
                        "description": "Name/identifier of the ransom note"
                    }
                },
                "required": ["group_name", "note_name"]
            }
        )
    ]

@app.call_tool()
async def handle_call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
    """
    Handle tool execution requests from MCP clients.
    
    This function routes tool calls to the appropriate API method and handles
    error cases gracefully.
    
    Args:
        name: The name of the tool to execute
        arguments: Optional dictionary of arguments for the tool
    
    Returns:
        List containing a TextContent object with the tool's response or error message
    """
    try:
        result = None
        
        # Route to the appropriate API method based on tool name
        if name == "list_sectors":
            result = await api_client.list_sectors()
            
        elif name == "list_groups":
            result = await api_client.list_groups()
            
        elif name == "get_group_info":
            # Validate required parameter exists
            if not arguments or "group_name" not in arguments:
                raise ValueError("group_name is required")
            result = await api_client.get_group_info(arguments["group_name"])
            
        elif name == "list_victims":
            # Extract filter parameters
            group = arguments.get("group") if arguments else None
            sector = arguments.get("sector") if arguments else None
            country = arguments.get("country") if arguments else None
            year = arguments.get("year") if arguments else None
            month = arguments.get("month") if arguments else None
            
            # Ensure at least one filter is provided
            if not any([group, sector, country, year, month]):
                raise ValueError("At least one filter parameter is required (group, sector, country, year, or month)")
            
            # Call API with filter parameters
            result = await api_client.list_victims(
                group=group,
                sector=sector,
                country=country,
                year=year,
                month=month
            )
            
        elif name == "get_victim_info":
            # Validate required parameter exists
            if not arguments or "victim_id" not in arguments:
                raise ValueError("victim_id is required")
            result = await api_client.get_victim_info(arguments["victim_id"])
            
        elif name == "search_victims":
            # Validate required search query exists
            if not arguments or "query" not in arguments:
                raise ValueError("query is required")
            # Extract optional filter parameters
            result = await api_client.search_victims(
                arguments["query"],
                arguments.get("group_name"),
                arguments.get("sector_name"),
                arguments.get("country")
            )
            
        elif name == "get_recent_victims":
            # Use provided order parameter or default to "discovered"
            order = arguments.get("order", "discovered") if arguments else "discovered"
            result = await api_client.get_recent_victims(order)
            
        elif name == "get_stats":
            # No parameters needed for general stats
            result = await api_client.get_stats()
            
        elif name == "get_ransomnotes":
            # Get all available ransom notes
            result = await api_client.get_ransomnotes()
            
        elif name == "get_ransomnotes_by_group":
            # Validate required parameter exists
            if not arguments or "group_name" not in arguments:
                raise ValueError("group_name is required")
            result = await api_client.get_ransomnotes_by_group(arguments["group_name"])
            
        elif name == "get_ransomnote_content":
            # Validate both required parameters exist
            if not arguments:
                raise ValueError("group_name and note_name are required")
            if "group_name" not in arguments:
                raise ValueError("group_name is required")
            if "note_name" not in arguments:
                raise ValueError("note_name is required")
            result = await api_client.get_ransomnote_content(
                arguments["group_name"],
                arguments["note_name"]
            )
            
        else:
            # Handle unknown tool names
            raise ValueError(f"Unknown tool: {name}")
        
        # Format and return the successful response
        if result:
            # Convert the result to formatted JSON string for readability
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2)
            )]
        else:
            # Handle case where API returns no data
            return [types.TextContent(
                type="text",
                text="No data returned from API"
            )]
        
    except httpx.HTTPStatusError as e:
        # Handle HTTP status errors (4xx, 5xx responses)
        logger.error(f"HTTP error calling tool {name}: {e}")
        error_msg = f"API Error {e.response.status_code}: {e.response.text}"
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]
    except httpx.HTTPError as e:
        # Handle other HTTP errors (connection issues, timeouts, etc.)
        logger.error(f"HTTP error calling tool {name}: {e}")
        return [types.TextContent(
            type="text",
            text=f"Error: Failed to fetch data from API - {str(e)}"
        )]
    except Exception as e:
        # Handle any other unexpected errors
        logger.error(f"Error calling tool {name}: {e}")
        return [types.TextContent(
            type="text",
            text=f"Error: {str(e)}"
        )]

async def main():
    """
    Main entry point for the MCP server.
    
    Sets up the stdio communication channels and runs the server with
    proper initialization options and capabilities.
    """
    # Create stdio streams for communication with MCP clients
    # This allows the server to communicate via standard input/output
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        # Run the server with the configured streams and initialization options
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="ransomware-live-mcp",  # Server identifier
                server_version="0.2.0",  # Current version of the server
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),  # Configure notification settings
                    experimental_capabilities={}  # No experimental features enabled
                )
            )
        )

# Entry point when script is run directly
if __name__ == "__main__":
    import asyncio
    # Run the async main function using asyncio
    asyncio.run(main())
