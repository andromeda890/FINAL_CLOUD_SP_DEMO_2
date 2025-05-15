
##### SUPER CRITICAL NOTE - THIS IS THE GOLDEN VERSION - DO NOT MESS UP - DATE MAY 11, 2025 - GOLD VERSION -DYNAMIC QUEIRY GEN RIGHT PANEL
# commit this one
# CRITICAL NOTE: THIS IS THE BASELINE CODE MODEL - DO NOT DESTROY
# TO DO ITEMS TO ENHANCE THIS CODE
# 1) ADD A DELETE BUTTON FOR NOW TO CLEAR CHAT HIST DB - PLACED ON THE LEFT PANEL - DONE IN 18
# 2) NOTE: SOURCE DOCUMENTS ARE NOW WELL-FORMATTED - DONE
# 3) DATA SPEAKING BY ITSELF - ADD TO THE RIGHT PANEL - SUGGESTED TOP THREE QUERIES
# 4) ADD THE ABILITY TO ORGANIZE CHAT HISTORY WITH CLASSIFICATION - AUTOMATIC CLASSIFICATION BY TOPIC
# 5) Need Assistant Output to be in nice Table Format - Critical - DONE in 18
# 6) Add LLM based Topic Modeling to show Topics  covered by current available documentation - Shows the topics in knowledge base -
# Later expand this into clickable topic to source document for easy consultation. - Helps with becoming familiar with knowledge base for
# more effective query
# 7) Convert Cloud Pricing documene to panda dataframe to storing data in SQLLite3 then use Text to SQL to interrogate that Data Separately
# 8) Critical - ADD AIKNOWLEGEFLOW.COM WITH COPYRIGHT AT THE TOP OF THE PAGE TO MAKE YOUR CLAIM FROM THE BEGINNING
# 9) ADD USER EMAIL ON STREAMLIT PRIVATE DEPLOYMENT FOR SECURE ACCESS TO ANINDA AND SOME COLLEAGUES
#10) Add LLM BASED WEB SEARCH CAPABILITY ON SPLUNK WEBSITES ONLY - SPLUNK SEARCH ENGINE TO CONSULT SPLUNK WEB RESOURCES


# Splunk Security Knowledge Explorer with Conversational UI
# This application leverages LlamaIndex cloud index for retrieving and displaying information
# from Splunk security documentation with source visualization

import os
import io
import base64
import sqlite3
import json
import re
import tempfile
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from datetime import datetime

from click import style
# Environment and API management
from dotenv import load_dotenv
import requests

# UI Framework
import streamlit as st

# LlamaIndex components
from llama_index.indices.managed.llama_cloud import LlamaCloudIndex
from llama_index.core.schema import NodeWithScore

# PDF visualization (if available)
try:
    import fitz  # PyMuPDF - for PDF visualization

    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False
    st.warning("PyMuPDF not installed. PDF page preview will not be available. Run: pip install pymupdf")

# First, add the OpenAI import
import openai
from openai import OpenAI
from collections import defaultdict

# === Configuration and Environment Setup ===

# App configuration

# Set up page configuration with wide layout
st.set_page_config(
    page_title="Splunk Security Knowledge Explorer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Customize the app appearance
st.markdown("""
<style>

.dataframe {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 0.9em;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
}

.dataframe thead th {
    background-color: #009879;
    color: #ffffff;
    text-align: left;
    font-weight: bold;
    padding: 12px 15px;
    border-bottom: 2px solid #dddddd;
}

.dataframe tbody tr {
    border-bottom: 1px solid #dddddd;
}

.dataframe tbody tr:nth-of-type(even) {
    background-color: #1e1e1e;
}

.dataframe tbody tr:last-of-type {
    border-bottom: 2px solid #009879;
}

.dataframe tbody td {
    padding: 12px 15px;
}

/* Markdown table styling */
.assistant-message table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 0.9em;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
}

.assistant-message th {
    background-color: #009879;
    color: #ffffff;
    text-align: left;
    font-weight: bold;
    padding: 12px 15px;
    border-bottom: 2px solid #dddddd;
}

.assistant-message table tr {
    border-bottom: 1px solid #dddddd;
}

.assistant-message table tr:nth-of-type(even) {
    background-color: #1e1e1e;
}

.assistant-message table tr:last-of-type {
    border-bottom: 2px solid #009879;
}

.assistant-message td {
    padding: 12px 15px;
}
#------------------------------ADD FOR MODIFICAITON HERE BELOW-------------------
.user-message {
    background-color: black;
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 15px;
    border-left: 5px solid #1E88E5;
}
.assistant-message {
    background-color: #000000;
    padding: 20px;
    border-radius: 15px;
    margin-bottom: 15px;
    border-left: 5px solid #26A69A;
}
.chat-header {
    font-size: 1.1em;
    margin-bottom: 8px;
    font-weight: bold;
}
.user-header {
    color: #1E88E5;
    background-color: rgba(30, 136, 229, 0.1);
    padding: 5px 10px;
    border-radius: 5px;
    display: inline-block;
}
.assistant-header {
    color: #26A69A;
    background-color: rgba(38, 166, 154, 0.1);
    padding: 5px 10px;
    border-radius: 5px;
    display: inline-block;
}

.source-text {
    font-size: 0.9em;
    line-height: 1.4;
    margin-bottom: 10px;
    color: #ddd;  /* Light gray text for better readability */
    font-family: 'Arial', sans-serif;
}

.source-text .source-section {
    margin-bottom: 10px;
    padding: 10px;
    border-left: 3px solid #4CAF50;  /* Green accent for sections */
    background-color: #1e1e1e;
    border-radius: 5px;
}

.source-text .source-heading {
    font-size: 1.1em;
    font-weight: bold;
    color: #fff;  /* White for headings */
    margin-bottom: 5px;
}

.source-text .source-bullet {
    margin-left: 15px;
    color: #bbb;  /* Light gray for bullet points */
}

.source-text strong {
    color: #FFC107;  /* Yellow for emphasized text */
}

/* Style for message content */
.message-content {
    font-size: 1.05em;
    line-height: 1.5;
}

</style>
""", unsafe_allow_html=True)

# Load environment variables
load_dotenv()
llamaindex_api_key = os.environ.get("LLAMAINDEX_API_KEY")
openai_api_key = os.environ.get("OPENAI_API_KEY")

# Validate API keys
if not llamaindex_api_key:
    st.error("LlamaIndex API key not found. Please set the LLAMAINDEX_API_KEY environment variable.")
    st.stop()
if not openai_api_key:
    st.error("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")
    st.stop()

# === LlamaIndex Setup ===

try:
    index = LlamaCloudIndex(
        name="new-sp-index-525",
        project_name="Default",
        organization_id="e092ea91-1530-4ce4-9e93-10dd4a06e8b9",
        api_key=llamaindex_api_key,
        model="gpt-4o",
        temperature=0.7,
        max_tokens=1024,
        top_p=0.95,
        frequency_penalty=0.0,
        presence_penalty=0.65,
        stream=True,
        verbose=False,

    )
except Exception as e:
    st.error(f"Failed to initialize LlamaCloudIndex: {e}")
    st.stop()


# === Database Functions ===

def check_and_update_schema():
    """Ensure the database has the required schema, updating it if necessary."""
    with sqlite3.connect("chat_history.db") as conn:
        # Check if the conversations table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='conversations'")
        if not cursor.fetchone():
            # Create conversations table
            conn.execute("""
                         CREATE TABLE conversations
                         (
                             id           TEXT PRIMARY KEY,
                             title        TEXT NOT NULL,
                             created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )
                         """)

            # Create messages table
            conn.execute("""
                         CREATE TABLE messages
                         (
                             id              INTEGER PRIMARY KEY AUTOINCREMENT,
                             conversation_id TEXT NOT NULL,
                             role            TEXT NOT NULL,
                             content         TEXT NOT NULL,
                             nodes_json      TEXT,
                             timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             FOREIGN KEY (conversation_id) REFERENCES conversations (id)
                         )
                         """)
            conn.commit()
            st.toast("Created new conversation database schema")

        # Check if we need to migrate from the old schema
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_history'")
        if cursor.fetchone():
            # Check if we've already done migration
            cursor = conn.execute("PRAGMA table_info(chat_history)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'migrated' not in columns:
                # Add migrated column
                conn.execute("ALTER TABLE chat_history ADD COLUMN migrated INTEGER DEFAULT 0")

                # Get unmigrated chats
                cursor = conn.execute("SELECT id, query, response, nodes_json FROM chat_history WHERE migrated = 0")
                chats = cursor.fetchall()

                # Migrate each chat
                for chat in chats:
                    chat_id, query, response, nodes_json = chat

                    # Create new conversation
                    conversation_id = str(uuid.uuid4())
                    truncated_query = query[:30] + "..." if len(query) > 30 else query
                    conn.execute(
                        "INSERT INTO conversations (id, title) VALUES (?, ?)",
                        (conversation_id, truncated_query)
                    )

                    # Add user message
                    conn.execute(
                        "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)",
                        (conversation_id, "user", query)
                    )

                    # Add assistant message
                    conn.execute(
                        "INSERT INTO messages (conversation_id, role, content, nodes_json) VALUES (?, ?, ?, ?)",
                        (conversation_id, "assistant", response, nodes_json)
                    )

                    # Mark as migrated
                    conn.execute("UPDATE chat_history SET migrated = 1 WHERE id = ?", (chat_id,))

                conn.commit()
                st.toast("Migrated existing chats to new conversation format")


def create_new_conversation(title: str) -> str:
    """
    Create a new conversation in the database.

    Args:
        title: Title for the conversation

    Returns:
        Conversation ID
    """
    conversation_id = str(uuid.uuid4())
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.execute(
                "INSERT INTO conversations (id, title) VALUES (?, ?)",
                (conversation_id, title)
            )
            conn.commit()
        return conversation_id
    except sqlite3.Error as e:
        st.error(f"Database error creating conversation: {e}")
        return None


def update_conversation_title(conversation_id: str, title: str) -> bool:
    """
    Update the title of an existing conversation.

    Args:
        conversation_id: ID of the conversation to update
        title: New title for the conversation

    Returns:
        Success status
    """
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.execute(
                "UPDATE conversations SET title = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
                (title, conversation_id)
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Database error updating conversation title: {e}")
        return False


def add_message_to_conversation(
        conversation_id: str,
        role: str,
        content: str,
        nodes: Optional[List[Union[NodeWithScore, Dict]]] = None,
        topic: Optional[str] = None
) -> bool:
    """
    Add a new message to an existing conversation with topic classification.

    Args:
        conversation_id: ID of the conversation
        role: 'user' or 'assistant'
        content: Message content
        nodes: Source nodes for assistant messages (optional)
        topic: Message topic classification (optional)

    Returns:
        Success status
    """
    try:
        # Update conversation timestamp
        with sqlite3.connect("chat_history.db") as conn:
            conn.execute(
                "UPDATE conversations SET last_updated = CURRENT_TIMESTAMP WHERE id = ?",
                (conversation_id,)
            )

            # Serialize nodes if provided
            nodes_json = None
            if nodes:
                nodes_data = []
                # Handle both NodeWithScore objects and dictionaries
                for node_item in nodes:
                    if isinstance(node_item, NodeWithScore):
                        node = node_item.node
                        nodes_data.append({
                            "content": node.get_content(metadata_mode="all"),
                            "metadata": node.metadata,
                            "score": node_item.score,
                            "node_id": node.node_id
                        })
                    else:
                        # Already a dictionary
                        nodes_data.append(node_item)
                nodes_json = json.dumps(nodes_data)

            # Classify topic for user messages if not provided
            if role == 'user' and topic is None:
                topic = classify_query_topic(content)

            # Insert the message with topic classification
            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, nodes_json, topic) VALUES (?, ?, ?, ?, ?)",
                (conversation_id, role, content, nodes_json, topic)
            )
            conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Database error adding message: {e}")
        return False
    except Exception as e:
        st.error(f"Error serializing nodes or classifying topic: {e}")
        return False


def get_conversations() -> List[Dict[str, Any]]:
    """
    Retrieve a list of all conversations.

    Returns:
        List of conversation dictionaries
    """
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT id, title, created_at, last_updated FROM conversations ORDER BY last_updated DESC"
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        st.error(f"Database error fetching conversations: {e}")
        return []


def get_conversation_messages(conversation_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve all messages for a specific conversation.

    Args:
        conversation_id: ID of the conversation

    Returns:
        List of message dictionaries
    """
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT id, role, content, nodes_json, timestamp FROM messages WHERE conversation_id = ? ORDER BY id ASC",
                (conversation_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        st.error(f"Database error fetching messages: {e}")
        return []


def get_user_messages_by_topic(conversation_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Retrieve user messages for a conversation grouped by topic.

    Args:
        conversation_id: ID of the conversation

    Returns:
        Dictionary with topics as keys and lists of messages as values
    """
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, content, topic, timestamp
                FROM messages
                WHERE conversation_id = ? AND role = 'user'
                ORDER BY id ASC
                """,
                (conversation_id,)
            )

            messages_by_topic = defaultdict(list)
            for row in cursor.fetchall():
                message = dict(row)
                topic = message.get('topic') or 'Uncategorized'
                messages_by_topic[topic].append(message)

            return messages_by_topic
    except sqlite3.Error as e:
        st.error(f"Database error fetching messages by topic: {e}")
        return {}


def deserialize_nodes(nodes_json: str) -> List[Dict[str, Any]]:
    """
    Convert JSON string of nodes back to a list of node objects.

    Args:
        nodes_json: JSON string containing serialized nodes

    Returns:
        List of dictionary representations of nodes
    """
    if not nodes_json:
        return []

    try:
        return json.loads(nodes_json)
    except json.JSONDecodeError as e:
        st.error(f"Error decoding nodes JSON: {e}")
        return []


# === PDF Helper Functions ===

def get_pdf_page_image(pdf_url: str, page_num: int) -> Optional[str]:
    """
    Fetch a PDF from a URL and extract a specific page as an image.

    Args:
        pdf_url: URL to the PDF file
        page_num: Page number to extract (0-indexed)

    Returns:
        Base64 encoded image of the PDF page or None if failed
    """
    if not PYMUPDF_AVAILABLE:
        return None

    try:
        # Attempt to download the PDF
        response = requests.get(pdf_url, timeout=10)
        if response.status_code != 200:
            return None

        # Create a temporary file to hold the PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_file:
            temp_file.write(response.content)
            temp_path = temp_file.name

        # Open the PDF with PyMuPDF
        doc = fitz.open(temp_path)

        if page_num >= doc.page_count:
            return None

        # Get the specified page
        page = doc.load_page(page_num)

        # Render the page to a PNG image
        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # 2x zoom factor

        # Convert pixmap to a PNG image
        img_bytes = pix.tobytes("png")

        # Clean up
        doc.close()
        os.unlink(temp_path)

        # Return base64 encoded image
        return base64.b64encode(img_bytes).decode('utf-8')

    except Exception as e:
        st.error(f"Failed to extract PDF page: {e}")
        return None


def extract_page_number(page_label: str) -> Optional[int]:
    """
    Convert a page label (e.g., 'Page 5' or '5') to a 0-indexed page number.

    Args:
        page_label: Page label from node metadata

    Returns:
        0-indexed page number or None if conversion fails
    """
    if not page_label:
        return None

    # Try to extract a number from the page label
    match = re.search(r'(\d+)', page_label)
    if match:
        try:
            # Convert to 0-indexed
            return int(match.group(1)) - 1
        except ValueError:
            return None
    return None


# === LlamaIndex Query Functions ===

def generate_response(input_text: str) -> Tuple[str, List[NodeWithScore]]:
    """
    Query LlamaIndex to generate a response with source nodes.

    Args:
        input_text: User's query

    Returns:
        Tuple of (response text, list of source nodes)
    """
    try:
        retriever = index.as_retriever()
        query_engine = index.as_query_engine()

        # Retrieve relevant nodes
        nodes = retriever.retrieve(input_text)

        # Generate response from nodes
        response = query_engine.query(input_text)

        return str(response), nodes

    except Exception as e:
        st.error(f"Error during query execution: {e}")
        return "Sorry, I encountered an error processing your query.", []


# === UI Components ===

def render_chat_message(role: str, content: str, message_id: Optional[int] = None):
    """
    Render a single chat message with appropriate styling.

    Args:
        role: 'user' or 'assistant'
        content: Message content
        message_id: Optional message ID for source button
    """
    if role == "user":
        st.markdown(f"""
        <div class="chat-header">
            <div class="user-header">👤 You</div>
        </div>
        <div class="user-message">
            <div class="message-content">{content}</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="chat-header">
            <div class="assistant-header">🤖 Assistant</div>
        </div>
        <div class="assistant-message">
            <div class="message-content">{content}</div>
        </div>
        """, unsafe_allow_html=True)

        # Add source button if message has an ID
        if message_id is not None:
            # Create a unique key for this button
            if st.button("View Source Documents and Relevance Score", key=f"source_btn_{message_id}"):
                st.session_state.selected_message_id = message_id




def format_source_content(content: str) -> str:
    """
    Format source content for better readability.

    Args:
        content: Raw source content text

    Returns:
        Formatted HTML for better readability
    """
    if not content:
        return "<p>No content available</p>"

    # Escape HTML characters
    content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Process content to make it more readable
    formatted_html = []

    # Split into paragraphs
    paragraphs = re.split(r'\n\s*\n', content)

    for paragraph in paragraphs:
        if not paragraph.strip():
            continue

        lines = paragraph.strip().split('\n')
        para_html = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Format headings
            if re.match(r'^[A-Z][A-Z\s]+[A-Z]:$', line) or re.match(r'^#+\s+.+$', line):
                line = f'<div class="source-heading">{line}</div>'

            # Format bullet points
            elif line.startswith('•') or line.startswith('*') or re.match(r'^\d+\.\s+', line):
                line = f'<div class="source-bullet">→ {line}</div>'

            # Format subheadings (all caps sections)
            elif re.match(r'^[A-Z][A-Z\s]+[A-Z](\s|$)', line) and len(line) < 80:
                line = f'<div class="source-heading">{line}</div>'

            # Highlight quotes
            else:
                line = re.sub(r'"([^"]+)"', r'"<strong>\1</strong>"', line)

            para_html.append(line)

        # Join lines with line breaks
        paragraph_html = '<br>'.join(para_html)
        formatted_html.append(f'<div class="source-section">{paragraph_html}</div>')

    # Join paragraphs with extra space
    return '<div class="source-text">' + ''.join(formatted_html) + '</div>'


def render_source_tabs(nodes: List[Dict[str, Any]]):
    """
    Render source tabs for a specific message.

    Args:
        nodes: List of node dictionaries
    """
    if not nodes:
        st.info("No source information available for this message.")
        return

    # Create more descriptive tab titles based on metadata
    tab_titles = []
    for i, node in enumerate(nodes):
        metadata = node.get("metadata", {})
        file_name = metadata.get("file_name", "")
        page_label = metadata.get("page_label", "")

        if file_name:
            # Truncate long filenames for tab display
            display_name = file_name
            if len(display_name) > 25:
                display_name = display_name[:22] + "..."

            if page_label:
                tab_titles.append(f"{display_name} (p.{page_label})")
            else:
                tab_titles.append(display_name)
        else:
            tab_titles.append(f"Source {i + 1}")

    # Create tabs for each source node
    if tab_titles:
        tabs = st.tabs(tab_titles)

        for i, (tab, node) in enumerate(zip(tabs, nodes)):
            with tab:
                metadata = node.get("metadata", {})

                # Display source metadata
                col1, col2 = st.columns([1, 1])

                with col1:
                    if metadata.get("file_name"):
                        st.markdown(f"**Source:** {metadata.get('file_name')}")

                    if metadata.get("document_title"):
                        st.markdown(f"**Document:** {metadata.get('document_title')}")

                    if metadata.get("page_label"):
                        st.markdown(f"**Page:** {metadata.get('page_label')}")

                with col2:
                    st.markdown(f"**Source Document Relevance Score:** {node.get('score', 0):.4f}")
                    if metadata.get("file_type"):
                        st.markdown(f"**File Type:** {metadata.get('file_type')}")

                # PDF visualization section
                if metadata.get("file_type") == "pdf" and metadata.get("file_path") and metadata.get("page_label"):
                    st.markdown("---")
                    st.markdown("#### PDF Preview")

                    file_path = metadata.get("file_path", "")
                    page_num = extract_page_number(metadata.get("page_label", ""))

                    #### Here I made image data change to get the pdf page image from node
                    if page_num is not None:
                        # Try to get PDF page image
                        # img_data = get_pdf_page_image(file_path, page_num)
                        img_data = node.get("image")

                        if img_data:
                            st.image(
                                f"data:image/png;base64,{img_data}",
                                caption=f"Page {metadata.get('page_label')} from {metadata.get('document_title', 'document')}",
                                use_column_width=True
                            )
                        else:
                            st.info("PDF preview not available.")

                # Display node content
                st.markdown("---")
                st.markdown("#### Source Text")
                st.markdown(
                    format_source_content(node.get("content", "No content available")),
                    unsafe_allow_html=True
                )
    else:
        st.info("No source nodes were retrieved for this query.")


def render_chat_messages_by_topic(conversation_id: str):
    """
    Render chat messages grouped by topic with classification headers.

    Args:
        conversation_id: ID of the conversation to display
    """
    # Get all messages for the conversation
    all_messages = get_conversation_messages(conversation_id)
    if not all_messages:
        return

    # Get user messages grouped by topic
    user_messages_by_topic = get_user_messages_by_topic(conversation_id)

    # If no topics are classified yet, just show regular chat view
    if not user_messages_by_topic or all(not msgs for msgs in user_messages_by_topic.values()):
        for message in all_messages:
            render_chat_message(message['role'], message['content'], message['id'])
        return

    # Create a mapping of user message IDs to their positions in the all_messages list
    user_message_positions = {}
    for i, msg in enumerate(all_messages):
        if msg['role'] == 'user':
            user_message_positions[msg['id']] = i

    # Sort topics by their first appearance in the conversation
    def get_first_message_position(topic_messages):
        first_msg = min(topic_messages, key=lambda m: m['id'])
        return user_message_positions.get(first_msg['id'], float('inf'))

    sorted_topics = sorted(
        [(topic, msgs) for topic, msgs in user_messages_by_topic.items() if msgs],
        key=lambda x: get_first_message_position(x[1])
    )

    # Render messages by topic
    for topic, topic_messages in sorted_topics:
        # Create a topic header with styling
        st.markdown(f"""
        <div style="background-color: #2E7D32; color: white; padding: 10px 15px; 
        border-radius: 10px; margin: 20px 0 15px 0; font-weight: bold; font-size: 1.1em;">
        🔍 {topic}
        </div>
        """, unsafe_allow_html=True)

        # Get all message IDs in this topic
        topic_message_ids = [msg['id'] for msg in topic_messages]

        # For each user message in this topic, find the corresponding exchange
        for user_msg in topic_messages:
            user_msg_pos = user_message_positions.get(user_msg['id'])

            if user_msg_pos is not None:
                # Render the user message
                render_chat_message('user', user_msg['content'], user_msg['id'])

                # Check if there's a corresponding assistant message
                if user_msg_pos + 1 < len(all_messages) and all_messages[user_msg_pos + 1]['role'] == 'assistant':
                    assistant_msg = all_messages[user_msg_pos + 1]
                    render_chat_message('assistant', assistant_msg['content'], assistant_msg['id'])


# Add these functions for topic classification

def classify_query_topic(query_text: str) -> str:
    """
    Uses OpenAI to classify the topic of a user query.

    Args:
        query_text: The text of the user's query

    Returns:
        The classified topic as a string
    """
    try:
        client = OpenAI(api_key=openai_api_key)

        prompt = f"""
        Classify the following Splunk security query into ONE of these categories:
        - Threat Detection
        - Security Monitoring
        - SIEM Configuration
        - Incident Response
        - Data Analysis
        - Compliance
        - User Management
        - General Splunk
        - Other

        Query: {query_text}

        Return ONLY the category name, nothing else.
        """

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a classifier that categorizes Splunk security related queries."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=20,
            temperature=0.1
        )

        # Extract the category from the response
        category = response.choices[0].message.content.strip()

        # Clean up the category (remove quotes, periods, etc.)
        category = category.strip('"\'.,;:')

        # If response doesn't match expected categories, default to "Other"
        valid_categories = [
            "Threat Detection", "Security Monitoring", "SIEM Configuration",
            "Incident Response", "Data Analysis", "Compliance",
            "User Management", "General Splunk", "Other"
        ]

        if category not in valid_categories:
            category = "Other"

        return category

    except Exception as e:
        st.error(f"Error classifying query: {e}")
        return "Other"  # Default if classification fails


def update_schema_for_topic_classification():
    """Update database schema to support topic classification of messages."""
    try:
        with sqlite3.connect("chat_history.db") as conn:
            # Check if the topic column exists in the messages table
            cursor = conn.execute("PRAGMA table_info(messages)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'topic' not in columns:
                # Add topic column to messages table
                conn.execute("ALTER TABLE messages ADD COLUMN topic TEXT")
                conn.commit()
                st.toast("Database schema updated to support topic classification")

                # Classify existing user messages
                cursor = conn.execute(
                    "SELECT id, content FROM messages WHERE role = 'user' AND topic IS NULL"
                )
                messages_to_classify = cursor.fetchall()

                for msg_id, content in messages_to_classify:
                    topic = classify_query_topic(content)
                    conn.execute(
                        "UPDATE messages SET topic = ? WHERE id = ?",
                        (topic, msg_id)
                    )

                conn.commit()

    except sqlite3.Error as e:
        st.error(f"Database error updating schema for topic classification: {e}")


# Function to generate suggested queries using OpenAI's LLM
def generate_suggested_queries(openai_api_key):
    """
    Use OpenAI to generate suggested queries based on existing queries in the database.
    Returns a list of suggested queries.
    """
    try:
        client = OpenAI(api_key=openai_api_key)

        # Get existing user queries from the database
        with sqlite3.connect("chat_history.db") as conn:
            cursor = conn.execute(
                "SELECT content FROM messages WHERE role = 'user' ORDER BY timestamp DESC LIMIT 20"
            )
            user_queries = cursor.fetchall()

        # If no queries exist, return some default suggestions
        if not user_queries:
            return [
                "What are the top security use cases for Splunk?",
                "How to detect ransomware using Splunk?",
                "Explain Splunk's data model for security analytics"
            ]

        # Extract the text of user queries
        queries = [query[0] for query in user_queries]
        query_examples = "\n".join(queries[:10])  # Use the 10 most recent queries

        # Create a prompt for OpenAI
        prompt = f"""
        Based on the following user queries, generate 3 new suggested queries that would be helpful for users exploring Splunk security knowledge:

        Previous Queries:
        {query_examples}

        Generate new suggested queries that are:
        1. Related to Splunk security topics
        2. Different from the existing queries
        3. Diverse in topics (detection, analytics, use cases, best practices)
        4. Phrased as clear questions or commands

        Return only the suggested queries, one per line.
        """

        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system",
                 "content": "You are a helpful assistant that generates relevant query suggestions for a Splunk security knowledge base."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=200
        )

        # Extract suggestions from the response
        suggested_text = response.choices[0].message.content.strip()
        suggested_queries = [q.strip() for q in suggested_text.split('\n') if q.strip()]

        # Return top 3 suggested queries
        return suggested_queries[:3]

    except Exception as e:
        print(f"Error generating suggestions: {e}")
        # Return fallback suggestions
        return [
            "What are the top security use cases for Splunk?",
            "How to detect ransomware using Splunk?",
            "Explain Splunk's data model for security analytics"
        ]


# Function to check if the suggested_queries table exists and create it if needed
def check_and_update_suggested_queries_schema():
    """Ensure the database has the required schema for suggested queries."""
    with sqlite3.connect("chat_history.db") as conn:
        # Check if the suggested_queries table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suggested_queries'")
        if not cursor.fetchone():
            # Create suggested_queries table
            conn.execute("""
                         CREATE TABLE suggested_queries
                         (
                             id         INTEGER PRIMARY KEY AUTOINCREMENT,
                             query      TEXT NOT NULL,
                             response   TEXT NOT NULL,
                             nodes_json TEXT,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                         )
                         """)
            conn.commit()
            st.toast("Created suggested queries table")


# Function to store a suggested query and its response in the database
def store_suggested_query(query, response, nodes):
    """
    Store a suggested query and its response in the database.

    Args:
        query: Suggested query text
        response: Response from LlamaIndex
        nodes: Source nodes for the response
    """
    try:
        # Serialize nodes if provided
        nodes_json = None
        if nodes:
            nodes_data = []
            for node_with_score in nodes:
                node = node_with_score.node
                nodes_data.append({
                    "content": node.get_content(metadata_mode="all"),
                    "metadata": node.metadata,
                    "score": node_with_score.score,
                    "node_id": node.node_id
                })
            nodes_json = json.dumps(nodes_data)

        with sqlite3.connect("chat_history.db") as conn:
            conn.execute(
                "INSERT INTO suggested_queries (query, response, nodes_json) VALUES (?, ?, ?)",
                (query, response, nodes_json)
            )
            conn.commit()

    except sqlite3.Error as e:
        st.error(f"Database error storing suggested query: {e}")
    except Exception as e:
        st.error(f"Error serializing nodes: {e}")


# Function to retrieve suggested queries from the database
def get_suggested_queries():
    """
    Retrieve the top 3 suggested queries and their responses from the database.

    Returns:
        List of dictionaries containing query, response, and nodes_json
    """
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT query, response, nodes_json FROM suggested_queries ORDER BY created_at DESC LIMIT 3"
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        st.error(f"Database error fetching suggested queries: {e}")
        return []


# Function to clear all suggested queries from the database
def clear_suggested_queries():
    """Clear all suggested queries from the database."""
    try:
        with sqlite3.connect("chat_history.db") as conn:
            conn.execute("DELETE FROM suggested_queries")
            conn.commit()
    except sqlite3.Error as e:
        st.error(f"Database error clearing suggested queries: {e}")


# Function to process suggested queries
def process_suggested_queries():
    """
    Generate new suggested queries, run them through LlamaIndex,
    and store results in the database.
    """
    # Make sure the suggested_queries table exists
    check_and_update_suggested_queries_schema()

    # Clear existing suggested queries
    clear_suggested_queries()

    # Generate new suggested queries
    suggested_queries = generate_suggested_queries(openai_api_key)

    # Process only the top 3 suggested queries
    for query in suggested_queries[:3]:
        # Run the query through LlamaIndex
        response, nodes = generate_response(query)

        # Store the query and response
        store_suggested_query(query, str(response), nodes)


def main():
    """Main application entry point."""


    # Customize the app appearance
    st.markdown("""
    <style>
    .user-message {
        background-color: black;
        padding: 15px;
        border-radius: 15px;
        margin-bottom: 10px;
        border-left: 5px solid #1E88E5;
    }
    .assistant-message {
        background-color: #000000;
        padding: 15px;
        border-radius: 15px;
        margin-bottom: 10px;
        border-left: 5px solid #26A69A;
    }
    .chat-header {
        font-size: 0.8em;
        color: #555;
        margin-bottom: 5px;
    }
    .suggested-query {
        background-color: #f0f2f6;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
        cursor: pointer;
        border-left: 3px solid #1E88E5;
    }
    </style>
    """, unsafe_allow_html=True)

    # Create a 3-column layout: left sidebar, main content, right suggestions column
    left_sidebar = st.sidebar

    # Main content layout - divide into main content and suggestions column
    main_col, suggestions_col = st.columns([4, 1])

    # Set up the sidebar
    left_sidebar.title("Splunk Security Knowledge Explorer")
    left_sidebar.image("https://www.splunk.com/content/dam/splunk-blogs/images/2017/02/splunk-logo.png", width=200)

    # Initialize the session state
    if 'conversation_id' not in st.session_state:
        st.session_state.conversation_id = None
    if 'selected_message_id' not in st.session_state:
        st.session_state.selected_message_id = None

    # Check and update schema
    check_and_update_schema()
    check_and_update_suggested_queries_schema()

    # Load conversations for the sidebar
    conversations = get_conversations()

    left_sidebar.markdown("""<div style= background-color:yellow><p style="font-size: 1.5em; color: red; margin-bottom: 8px;">Begin a New Conversation</p></div>""",
            unsafe_allow_html=True)

    # New conversation button
    if left_sidebar.button("➕New Conversation",use_container_width=True):
        # Create a new conversation with placeholder title
        new_id = create_new_conversation("New Conversation")
        st.session_state.conversation_id = new_id
        st.session_state.selected_message_id = None
        st.rerun()

    # Display conversation list
    left_sidebar.markdown("### Your Conversation History")


    for conv in conversations:
        created_date = datetime.fromisoformat(conv['created_at'].replace('Z', '+00:00')) if isinstance(
            conv['created_at'], str) else conv['created_at']
        date_str = created_date.strftime("%Y-%m-%d") if created_date else "Unknown date"
        if left_sidebar.button(f"{conv['title']} ({date_str})", key=f"conv_{conv['id']}", use_container_width=True):
            st.session_state.conversation_id = conv['id']
            st.session_state.selected_message_id = None
            st.rerun()

    # Right column for suggested queries (always visible)
    with suggestions_col:

        st.markdown(
            """<div style= background-color:purple><p style="font-size: 0.8em; color: white; margin-bottom: 8px;">Copyright ©2025 aiknowledgeflow.com - All Rights Reserved. Prototype as Proof of Concept Developed By aiknowledgeflow.com Consulting </p></div>""",
            unsafe_allow_html=True)

        st.markdown("")
        st.markdown(
            """<div style= background-color:white><p style="font-size: 1.2em; color: red; margin-bottom: 8px;">Splunk Security Knowledge Explorer </p></div>""",
            unsafe_allow_html=True)

        st.markdown("""
                   Welcome to the conversational Splunk Security Knowledge Explorer! 
                   You can ask questions about Splunk security topics such as:
                   * Top cyber threats and how to detect them
                   * Industry Threat Intelligence in 2025
                   * Splunk Security Telemetry for Customers
                   * Splunk Security Telemetry and Industry-based Cost Savings Estimate
                   * Splunk Customer Use Cases Demonstrating ROI based on Splunk Product Costs
                   """)
       # st.markdown("# AI Suggested Queries Based on Your Conversation")
       # st.markdown(
         #   """<div style= background-color:white><p style="font-size: 1.2em; color: red; margin-bottom: 8px;">Start a new conversation or select one from below: </p></div>""",
         #   unsafe_allow_html=True)

        st.markdown(
            """<div style= background-color:yellow><p style="font-size: 1.0em; color: red; margin-bottom: 8px;">AI Suggested Queries Based on Your Conversation - Just Click One or Generate New Ones!! </p></div>""",
            unsafe_allow_html=True)

        # Get suggested queries
        suggested_queries = get_suggested_queries()

        if suggested_queries:
            for i, query in enumerate(suggested_queries):
                query_text = query.get('query', '')
                query_id = query.get('id', '')

                # Create a unique key for this query button
                # Use a combination of index, id (if available), and a timestamp-based unique identifier
                button_key = f"sugg_query_{i}_{query_id}_{hash(query_text)}"

                # Display as a styled container with click behavior
                if st.button(query_text, key=button_key, use_container_width=True):
                    # When clicked, use this query
                    if st.session_state.conversation_id:
                        # Add user message with this query
                        add_message_to_conversation(st.session_state.conversation_id, "user", query_text)

                        # Generate response
                        with st.spinner("Thinking..."):
                            response, nodes = generate_response(query_text)

                        # Add assistant response
                        add_message_to_conversation(st.session_state.conversation_id, "assistant", response, nodes)

                        # If this is a new conversation, update the title
                        messages = get_conversation_messages(st.session_state.conversation_id)
                        if len(messages) <= 2:  # Only user message + new response
                            title = query_text[:30] + "..." if len(query_text) > 30 else query_text
                            update_conversation_title(st.session_state.conversation_id, title)

                        st.rerun()
                    else:
                        # Create a new conversation with this query
                        new_id = create_new_conversation("New Conversation")
                        st.session_state.conversation_id = new_id

                        # Add the message and schedule a rerun to handle the response
                        add_message_to_conversation(new_id, "user", query_text)
                        st.rerun()
        else:
            st.write("No suggested queries available")

        # Button to generate new suggestions
        if st.button("Generate New Suggestions", key="gen_sugg_btn", use_container_width=True):
            # Process and generate new suggested queries
            process_suggested_queries()
            st.rerun()

        # Button to clear suggestions
        if st.button("Clear Suggestions", key="clear_sugg_btn", use_container_width=True):
            clear_suggested_queries()
            st.rerun()

    # Main content area
    with main_col:
        if st.session_state.conversation_id:
            # Get current conversation
            current_conversation = next((c for c in conversations if c['id'] == st.session_state.conversation_id), None)
            if current_conversation:
                # Display conversation title
                st.title(current_conversation['title'])
            else:
                st.title("New Conversation")

            # Load messages for the current conversation
            messages = get_conversation_messages(st.session_state.conversation_id)

            # Create a container for chat history
            chat_container = st.container(height=400, border=False)

            # Display messages
            with chat_container:
                for message in messages:
                    render_chat_message(message['role'], message['content'], message['id'])

            # Display sources if a message is selected
            if st.session_state.selected_message_id:
                selected_message = next((m for m in messages if m['id'] == st.session_state.selected_message_id), None)
                if selected_message and selected_message.get('nodes_json'):
                    st.markdown("---")
                    st.subheader("Source Information")
                    nodes = deserialize_nodes(selected_message['nodes_json'])
                    render_source_tabs(nodes)

                    # Close button for sources
                    if st.button("Close Sources", use_container_width=True):
                        st.session_state.selected_message_id = None
                        st.rerun()

            # User input
            st.markdown("---")
            user_input = st.text_area("Your message:", height=100, placeholder="Ask about Splunk security topics...")

            # Send button
            col1, col2 = st.columns([1, 6])
            with col1:
                send_pressed = st.button("Send", type="primary", use_container_width=True)

            if send_pressed and user_input.strip():
                # Clear the input
                input_value = user_input.strip()

                # Add user message to conversation
                add_message_to_conversation(st.session_state.conversation_id, "user", input_value)

                # Generate response
                with st.spinner("Thinking..."):
                    response, nodes = generate_response(input_value)

                # Add assistant response to conversation
                add_message_to_conversation(st.session_state.conversation_id, "assistant", response, nodes)

                # If this is the first message, update the conversation title
                if len(messages) == 0:
                    title = input_value[:30] + "..." if len(input_value) > 30 else input_value
                    update_conversation_title(st.session_state.conversation_id, title)

                # After a new query is processed, update suggested queries
                process_suggested_queries()

                # Refresh the page
                st.rerun()
        else:
            # Welcome screen - no conversation selected
            st.title("Splunk Security Knowledge Explorer")
            st.markdown("""
                       Welcome to the conversational Splunk Security Knowledge Explorer! 

                       You can ask questions about Splunk security topics such as:
                        * Top cyber threats and how to detect them
                        * Industry Threat Intelligence in 2025
                        * Splunk Security Telemetry for Customers
                        * Splunk Security Telemetry and Industry-based Cost Savings Estimate
                        * Splunk Customer Use Cases Demonstrating ROI based on Splunk Product Costs

                       Start a new conversation or select an existing one from the sidebar.
                       """)

            # Quick start button
          #  if st.button("Start New Conversation", type="primary"):
            #    new_id = create_new_conversation("New Conversation")
             #   st.session_state.conversation_id = new_id
              #  st.rerun()

# Run the application
if __name__ == "__main__":
    main()