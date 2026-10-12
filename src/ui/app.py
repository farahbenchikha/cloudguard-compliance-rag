import os
import sys
import re
from pathlib import Path
from dotenv import load_dotenv
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# LlamaIndex & Qdrant
from qdrant_client import QdrantClient
from llama_index.core import VectorStoreIndex, StorageContext, Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.qdrant import QdrantVectorStore
from llama_index.llms.ollama import Ollama

load_dotenv()

# Configuration Streamlit
st.set_page_config(
    page_title="CloudGuard AI | DevSecOps Compliance Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "cis_benchmarks")
EMBED_MODEL_NAME = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


@st.cache_resource
def load_rag_engine():
    """Initialise le modèle d'embedding et la connexion Qdrant en cache."""
    embed_model = HuggingFaceEmbedding(model_name=EMBED_MODEL_NAME)
    Settings.embed_model = embed_model
    
    llm = Ollama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        request_timeout=300.0,
        temperature=0.1
    )
    Settings.llm = llm

    client = QdrantClient(url=QDRANT_URL)
    vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)
    index = VectorStoreIndex.from_vector_store(vector_store=vector_store, embed_model=embed_model)
    return index, llm


def extract_resource_types(tf_code: str) -> list:
    matches = re.findall(r'resource\s+"([^"]+)"', tf_code)
    return list(set(matches))


# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ CloudGuard AI")
    st.caption("DevSecOps & Cloud Compliance Copilot")
    st.divider()

    st.subheader("⚙️ État des Services")
    st.success(f"● **Vector DB** : Qdrant (`{COLLECTION_NAME}`)")
    st.info(f"● **Embeddings** : Local (`{EMBED_MODEL_NAME}`)")
    st.warning(f"● **LLM** : Ollama (`{OLLAMA_MODEL}`)")
    
    st.divider()
    st.subheader("📂 Code Terraform à auditer")
    input_choice = st.radio("Mode d'analyse :", ["Exemples TerraGoat", "Importer un fichier .tf"])
    
    selected_code = ""
    file_label = ""
    
    if input_choice == "Exemples TerraGoat":
        demo_files = {
            "Amazon S3 (Stockage public / sans chiffrement)": "data/test_iac/terragoat/terraform/aws/s3.tf",
            "AWS IAM (Politiques admin excessives)": "data/test_iac/terragoat/terraform/aws/iam.tf",
            "Amazon EC2 (Secrets en clair dans User Data)": "data/test_iac/terragoat/terraform/aws/ec2.tf",
        }
        chosen_demo = st.selectbox("Choisir une ressource :", list(demo_files.keys()))
        path = Path(demo_files[chosen_demo])
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                selected_code = f.read()
            file_label = path.name
    else:
        uploaded_file = st.file_uploader("Glissez un fichier Terraform (.tf)", type=["tf"])
        if uploaded_file is not None:
            selected_code = uploaded_file.read().decode("utf-8")
            file_label = uploaded_file.name


# --- MAIN VIEW ---
st.title("🛡️ CloudGuard AI : DevSecOps & Cloud Compliance Copilot")
st.markdown("Plateforme RAG souveraine d'audit de sécurité automatisé contre les **CIS Amazon Web Services Foundations Benchmarks v3.0**")

col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader(f"📄 Code Terraform HCL (`{file_label or 'Aucun fichier'}`)")
    code_area = st.text_area("Code source :", value=selected_code, height=450)
    start_audit = st.button("🚀 Lancer l'Audit de Sécurité RAG", type="primary", use_container_width=True)

with col_right:
    st.subheader("📊 Rapport d'Audit & Remédiations")
    
    if start_audit and code_area:
        with st.spinner("🔍 Recherche sémantique dans Qdrant & Analyse par Llama 3..."):
            try:
                index, llm = load_rag_engine()
                
                # 1. Extraction dynamique
                resources = extract_resource_types(code_area)
                res_str = ", ".join(resources) if resources else "AWS Resources"
                
                # 2. Retrieval
                query = f"AWS security compliance hardening best practices for {res_str} access policies privileges and misconfigurations"
                retriever = index.as_retriever(similarity_top_k=4)
                relevant_nodes = retriever.retrieve(query)
                context_str = "\n\n---\n\n".join([node.node.get_content() for node in relevant_nodes])
                
                # Affichage des règles CIS
                with st.expander("🔍 Règles CIS Benchmark extraites de Qdrant", expanded=True):
                    for node in relevant_nodes:
                        st.markdown(f"- **Règle {node.node.metadata.get('rule_id', 'N/A')}** : {node.node.metadata.get('title', 'N/A')}")
                
                # 3. Generation Prompt
                prompt = f"""Tu es un Lead Cloud Security Architect. Audite ce code Terraform avec le référentiel CIS fourni.

### RÈGLES CIS OFFICIELLES APPLICABLES :
{context_str}

### CODE TERRAFORM À AUDITER :
```terraform
{code_area}
```

### INSTRUCTIONS DE RAPPORT :
Pour chaque ressource non conforme détectée :
1. **Ressource** : nom de la ressource.
2. **Règle CIS violée** : ID exact (ex: CIS 1.16, CIS 2.1.1) et titre.
3. **Sévérité** : [CRITICAL] ou [HIGH].
4. **Risque** : Explication concise du danger.
5. **Remédiation HCL** : Code Terraform corrigé.
"""
                response_placeholder = st.empty()
                full_text = ""
                
                for chunk in llm.stream_complete(prompt):
                    full_text += chunk.delta
                    response_placeholder.markdown(full_text + "▌")
                
                response_placeholder.markdown(full_text)
                
                st.download_button(
                    label="📥 Télécharger le Rapport d'Audit (.md)",
                    data=full_text,
                    file_name=f"audit_{file_label or 'report'}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
                
            except Exception as e:
                st.error(f"Erreur durant l'audit : {e}")
    elif not code_area:
        st.info("👈 Veuillez sélectionner ou coller du code Terraform à gauche pour démarrer.")
