#!/usr/bin/env python3
"""
Scrape 500 most recently updated Dockerfiles from GitHub and save them to sample_data/general/
"""

import os
import sys
import time
import requests
import json
from pathlib import Path
from urllib.parse import quote
from typing import List, Dict, Optional

# GitHub API configuration
GITHUB_API_BASE = "https://api.github.com"
SEARCH_ENDPOINT = f"{GITHUB_API_BASE}/search/code"
RATE_LIMIT_ENDPOINT = f"{GITHUB_API_BASE}/rate_limit"

# Configuration
TARGET_COUNT = 500
RESULTS_PER_PAGE = 100  # GitHub API max
OUTPUT_DIR = Path(__file__).parent / "general"
OUTPUT_DIR.mkdir(exist_ok=True)

# GitHub token (optional, but recommended for higher rate limits)
# Set via environment variable: export GITHUB_TOKEN=your_token_here
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


def get_headers() -> Dict[str, str]:
    """Get HTTP headers for GitHub API requests."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "DockerGuard-Scraper"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def check_rate_limit() -> Optional[Dict]:
    """Check current GitHub API rate limit status."""
    try:
        response = requests.get(RATE_LIMIT_ENDPOINT, headers=get_headers())
        response.raise_for_status()
        data = response.json()
        core = data.get("resources", {}).get("core", {})
        remaining = core.get("remaining", 0)
        reset_time = core.get("reset", 0)
        
        print(f"Rate limit: {remaining} requests remaining")
        if remaining < 10:
            wait_time = max(0, reset_time - int(time.time()))
            if wait_time > 0:
                print(f"Rate limit low. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
        
        return core
    except Exception as e:
        print(f"Warning: Could not check rate limit: {e}")
        return None


def search_dockerfiles(page: int = 1, per_page: int = RESULTS_PER_PAGE) -> Dict:
    """
    Search for Dockerfiles on GitHub, sorted by recently updated.
    
    Args:
        page: Page number (1-indexed)
        per_page: Results per page (max 100)
    
    Returns:
        API response JSON
    """
    # Search for files named "Dockerfile" (case-sensitive)
    # Sort by indexed (which includes recently updated files)
    query = "filename:Dockerfile"
    
    params = {
        "q": query,
        "sort": "indexed",  # Sort by when the file was last indexed (recently updated)
        "order": "desc",
        "per_page": min(per_page, RESULTS_PER_PAGE),
        "page": page
    }
    
    url = f"{SEARCH_ENDPOINT}?q={quote(query)}&sort=indexed&order=desc&per_page={params['per_page']}&page={page}"
    
    try:
        response = requests.get(url, headers=get_headers())
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            print(f"Rate limit exceeded. Response: {response.text}")
            check_rate_limit()
        raise
    except Exception as e:
        print(f"Error searching Dockerfiles: {e}")
        raise


def get_file_content(file_url: str) -> Optional[str]:
    """
    Download the raw content of a file from GitHub.
    
    Args:
        file_url: GitHub API URL for the file
    
    Returns:
        File content as string, or None if error
    """
    try:
        response = requests.get(file_url, headers=get_headers())
        response.raise_for_status()
        data = response.json()
        # Decode base64 content
        import base64
        content = base64.b64decode(data.get("content", "")).decode("utf-8")
        return content
    except Exception as e:
        print(f"Error downloading file {file_url}: {e}")
        return None


def sanitize_filename(repo_name: str, path: str) -> str:
    """
    Create a safe filename from repository name and path.
    
    Args:
        repo_name: Repository full name (e.g., "owner/repo")
        path: File path in repository
    
    Returns:
        Sanitized filename
    """
    # Replace slashes and other problematic characters
    safe_repo = repo_name.replace("/", "_").replace("\\", "_")
    safe_path = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
    
    # Limit length
    filename = f"{safe_repo}_{safe_path}"
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


def save_dockerfile(content: str, filename: str) -> bool:
    """
    Save Dockerfile content to disk.
    
    Args:
        content: File content
        filename: Base filename (will add .dockerfile extension if needed)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure filename has an extension
        if not filename.endswith((".dockerfile", ".Dockerfile")):
            filename = f"{filename}.dockerfile"
        
        filepath = OUTPUT_DIR / filename
        
        # Handle duplicates by appending number
        counter = 1
        original_filepath = filepath
        while filepath.exists():
            base = original_filepath.stem
            ext = original_filepath.suffix
            filepath = OUTPUT_DIR / f"{base}_{counter}{ext}"
            counter += 1
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        return True
    except Exception as e:
        print(f"Error saving file {filename}: {e}")
        return False


def main():
    """Main scraping function."""
    print(f"Starting to scrape {TARGET_COUNT} Dockerfiles from GitHub...")
    print(f"Output directory: {OUTPUT_DIR}")
    
    if GITHUB_TOKEN:
        print("Using GitHub token for authentication (higher rate limits)")
    else:
        print("Warning: No GITHUB_TOKEN set. Using unauthenticated requests (lower rate limits)")
        print("Set GITHUB_TOKEN environment variable for better performance")
    
    check_rate_limit()
    
    collected_files = []
    page = 1
    total_collected = 0
    
    while total_collected < TARGET_COUNT:
        print(f"\nFetching page {page}...")
        
        try:
            search_results = search_dockerfiles(page=page)
            
            total_count = search_results.get("total_count", 0)
            items = search_results.get("items", [])
            
            if page == 1:
                print(f"Total Dockerfiles found: {total_count}")
            
            if not items:
                print("No more results available")
                break
            
            print(f"Processing {len(items)} files from page {page}...")
            
            for item in items:
                if total_collected >= TARGET_COUNT:
                    break
                
                repo_name = item.get("repository", {}).get("full_name", "unknown/unknown")
                file_path = item.get("path", "Dockerfile")
                file_url = item.get("url", "")
                html_url = item.get("html_url", "")
                
                print(f"  [{total_collected + 1}/{TARGET_COUNT}] Downloading: {repo_name}/{file_path}")
                
                # Download file content
                content = get_file_content(file_url)
                
                if content:
                    # Basic validation: check if it looks like a Dockerfile
                    # (starts with common Dockerfile instructions)
                    first_lines = content.strip().split("\n")[:5]
                    dockerfile_keywords = ["FROM", "RUN", "COPY", "ADD", "WORKDIR", "ENV", "EXPOSE"]
                    is_dockerfile = any(
                        line.strip().split()[0].upper() in dockerfile_keywords 
                        for line in first_lines 
                        if line.strip()
                    )
                    
                    if is_dockerfile:
                        filename = sanitize_filename(repo_name, file_path)
                        if save_dockerfile(content, filename):
                            collected_files.append({
                                "repo": repo_name,
                                "path": file_path,
                                "url": html_url,
                                "filename": filename
                            })
                            total_collected += 1
                        else:
                            print(f"    Failed to save file")
                    else:
                        print(f"    Skipped: Doesn't appear to be a valid Dockerfile")
                else:
                    print(f"    Failed to download content")
                
                # Be nice to GitHub API - small delay between requests
                time.sleep(0.1)
            
            # Check if we've exhausted all results
            if len(items) < RESULTS_PER_PAGE:
                print("Reached end of available results")
                break
            
            page += 1
            
            # Rate limit protection
            if page % 5 == 0:
                check_rate_limit()
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            break
        except Exception as e:
            print(f"Error on page {page}: {e}")
            print("Waiting 5 seconds before retrying...")
            time.sleep(5)
            continue
    
    print(f"\n\nScraping complete!")
    print(f"Successfully collected {total_collected} Dockerfiles")
    print(f"Files saved to: {OUTPUT_DIR}")
    
    # Save metadata
    metadata_file = OUTPUT_DIR / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "total_collected": total_collected,
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files": collected_files
        }, f, indent=2)
    
    print(f"Metadata saved to: {metadata_file}")


if __name__ == "__main__":
    main()

