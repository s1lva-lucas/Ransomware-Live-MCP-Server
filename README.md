# Ransomware Live MCP Server

## Overview
This project implements an MCP (Model Context Protocol) server that integrates with the [Ransomware.live Pro API](https://api-pro.ransomware.live). It exposes various API endpoints as MCP tools, allowing clients to query ransomware-related data such as groups, victims, sectors, statistics, and ransom notes.

## Features
- **List Sectors**: Retrieve all tracked sectors/industries.
- **List Groups**: Retrieve all ransomware groups.
- **Get Group Info**: Detailed information about a specific ransomware group.
- **List Victims**: List ransomware victims with various filters (requires at least one filter).
- **Get Victim Info**: Detailed information about a specific victim.
- **Search Victims**: Search victims by name, domain, or other criteria with optional filters.
- **Get Recent Victims**: Recently discovered or published victims.
- **Get Stats**: General ransomware statistics.
- **Get Ransom Notes**: List all available ransom notes.
- **Get Ransom Notes by Group**: Ransom notes from a specific group.
- **Get Ransom Note Content**: Full content of a specific ransom note.

## Code Structure
- **`RansomwareLiveAPI` class**: Handles HTTP requests to the Ransomware.live API using `httpx`.
- **MCP Server Initialization**: Creates an MCP server instance and registers tools.
- **Tool Handlers**:
  - `@app.list_tools()`: Returns metadata for all available tools.
  - `@app.call_tool()`: Executes the requested tool by calling the corresponding API method.
- **Main Function**: Runs the MCP server over stdio.

## Deployment in CLINE
1. **Clone the repository** into your MCP servers directory.
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up environment variables**:
   - Create a `.env` file in the project root:
     ```
     RANSOMWARE_LIVE_API_KEY=your_api_key_here
     ```
4. **Configure CLINE**:
   - Add the MCP server to your CLINE configuration (`cline_mcp_settings.json`):
     ```json
     {
       "servers": {
         "ransomware-live": {
           "command": "python",
           "args": ["path/to/server.py"]
         }
       }
     }
     ```
5. **Run CLINE** and the MCP server will be available for use.

## Example Usage
Once deployed, you can call tools like:

### List all ransomware groups:
```json
{
  "name": "list_groups",
  "arguments": {}
}
```

### Get information about a specific group:
```json
{
  "name": "get_group_info",
  "arguments": { "group_name": "lockbit3" }
}
```

### List victims with filters (at least one required):
```json
{
  "name": "list_victims",
  "arguments": { 
    "q": "healthcare",
    "year": "2024",
    "month": "01"
  }
}
```

### Search for specific victims:
```json
{
  "name": "search_victims",
  "arguments": { 
    "query": "hospital",
    "group_name": "alphv",
    "country": "USA"
  }
}
```

### Get recent victims:
```json
{
  "name": "get_recent_victims",
  "arguments": { "order": "discovered" }
}
```

### Get ransom note content:
```json
{
  "name": "get_ransomnote_content",
  "arguments": { 
    "group_name": "lockbit3",
    "note_name": "readme.txt"
  }
}
```

## License
This project is provided for educational and research purposes only.
