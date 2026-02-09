import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="AhnLab TG 릴리즈노트 아카이브 Pro v35.21", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    .security-comp { background-color: #E8F5E9; padding: 10px; border-radius: 6px; margin-bottom: 5px; font-family: monospace; font-size: 14px; border: 1px solid #C8E6C9; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- 3. [통합 엔진] v35.21 (정규식 오류 수정판) ---

def clean_text(text):
    if not text: return ""
    return re.sub(r'\s+', ' ', str(text).replace('\n', ' ')).strip()

def repair_content(text):
    if not text: return ""
    text = re.sub(r'([a-zA-Z])\s*[\*\-]\s*([a-zA-Z])', r'\1\2', text)
    text = re.sub(r'([가-힣])\s*[\*\-]\s*([가-힣])', r'\1\2', text)
    text = re.sub(r'\(\s+', '(', text)
    text = re.sub(r'\s+\)', ')', text)
    return text

def split_long_blob(text):
    """
    [수정됨] 캡처 그룹을 사용하여 문장을 분리하고 다시 조립
    """
    if len(text) < 50: return [text]

    # 분할 기준 키워드 (괄호로 묶어서 split 결과에 포함되게 함)
    # 뒤에 공백이나 문장 끝이 오는 경우만 매칭하여 오탐 방지
    keywords = r'(개선|수정|추가|제공|삭제|변경|현상|않음|실패|실패함|완료)(?=\s|$)'
    
    # 1. 분할 (내용, 키워드, 내용, 키워드... 순으로 리스트 생성됨)
    parts = re.split(keywords, text)
    
    results = []
    current_sent = ""
    
    for part in parts:
        if not part: continue
        
        # 키워드인지 확인 (정규식 패턴에 있는 단어인지)
        if re.match(r'^(개선|수정|추가|제공|삭제|변경|현상|않음|실패|실패함|완료)$', part):
            current_sent += part # 문장에 키워드 붙임 (문장 완성)
            results.append(current_sent.strip())
            current_sent = "" # 초기화
        else:
            current_sent += part # 문장 내용 누적
            
    # 남은 찌꺼기 처리
    if current_sent.strip():
        results.append(current_sent.strip())
            
    # 너무 짧은 문장(5글자 미만) 필터링
    return [s for s in results if len(s) > 5]

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        for page in pdf.pages:
            p_text = page.extract_text()
            if p_text:
                p_text = re.sub(r'\d+\s*/\s*\d+', '', p_text)
                full_raw += p_text + "\n"
        
        lines = full_raw.split('\n')
        
        current_type = ""
        current_cat = ""
        current_desc = []
        
        ignore_keywords = [
            '[릴리즈노트]', '제약사항', '제약 사항', '다운로드', '관련 문서', 'Build', 'Last Updated', 
            'http', 'TrusGuard_', 'AhnLab', 'Copyright', 'All rights reserved', '개인정보처리방침',
            '카테고리 검색', '구독하기', '만듦', '편집된 시간', 'WARNING', '반출', '동의하는 자',
            '제품명', '펌웨어', '해쉬값', '클라이언트', 'for Windows', 'for Android', 'for iOS', 
            'for Linux', 'for MacOS', 'package', '서명값', 'DIP Client', '릴리스 일시', '주요 내용'
        ]
        cat_keywords = ['System', 'Network', 'SSL', 'VPN', 'IPSec', 'Dashboard', 'Log', 'Policy', 'Object', 'Monitor', 'LDAP', 'IP']

        for line in lines:
            line = line.strip()
            if not line: continue
            
            if any(k in line for k in ignore_keywords): continue
            if re.match(r'^\d{4}\.', line): continue
            if '>' in line and 'TrusGuard' in line: continue
            
            is_new_start = False
            found_type = ""
            found_cat = ""
            rest_line = ""

            tag_match = re.match(r'^[•\-]?\s*(\[[^\]]+\])\s*(.*)', line)
            icon_start = any(line.startswith(x) for x in ['↑', '+', '🔼'])
            
            cat_start_match = None
            first_word = line.split()[0] if line else ""
            if any(k in first_word for k in cat_keywords):
                cat_start_match = True
            
            bug_header = "Bug 수정" in line or "버그 수정" in line

            if tag_match:
                tag = tag_match.group(1)
                if '릴리즈' not in tag and '제약' not in tag:
                    is_new_start = True
                    found_type = tag
                    rest_line = tag_match.group(2)
            elif icon_start:
                is_new_start = True
                if 'Improvement' in line: 
                    found_type = '[개선]'
                    rest_line = line.replace('Improvement', '').replace('🔼', '').strip()
                elif line.startswith('+'): found_type = '[신규]'
                else: found_type = '[개선]'
                if not rest_line: rest_line = line[1:].strip()
            elif bug_header:
                current_type = "[이슈]"
                current_desc = [] 
                continue 
            elif cat_start_match:
                is_new_start = True
                found_type = current_type
                current_cat = first_word
                rest_line = line[len(first_word):].strip()
                found_cat = current_cat

            if is_new_start:
                if current_desc:
                    full_desc = " ".join(current_desc)
                    full_desc = repair_content(full_desc)
                    
                    split_sentences = split_long_blob(full_desc)
                    
                    for sent in split_sentences:
                        if len(sent) > 5:
                            final_type = current_type.replace('↑', '개선').replace('+', '신규').replace('🔼', '개선').replace('[', '').replace(']', '')
                            type_str = f"[{final_type}]" if final_type and final_type != "항목" else ""
                            cat_str = f" {current_cat}" if current_cat else ""
                            
                            if not type_str and not cat_str: formatted = f"* {sent}"
                            else: formatted = f"{type_str}{cat_str} * {sent}"
                            
                            if formatted not in extracted_data: extracted_data.append(formatted)

                current_type = found_type
                if found_cat: current_cat = found_cat
                elif tag_match or icon_start: current_cat = "" 
                current_desc = [rest_line] if rest_line else []
            else:
                current_desc.append(line)
        
        if current_desc:
            full_desc = " ".join(current_desc)
            full_desc = repair_content(full_desc)
            split_sentences = split_long_blob(full_desc)
            for sent in split_sentences:
                if len(sent) > 5:
                    final_type = current_type.replace('↑', '개선').replace('+', '신규').replace('🔼', '개선').replace('[', '').replace(']', '')
                    type_str = f"[{final_type}]" if final_type and final_type != "항목" else ""
                    cat_str = f" {current_cat}" if current_cat else ""
                    if not type_str and not cat_str: formatted = f"* {sent}"
                    else: formatted = f"{type_str}{cat_str} * {sent}"
                    extracted_data.append(formatted)

        v = re.search(r'TrusGuard\s+v?([0-9\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl_match_full = re.search(r'(OpenSSL.*)', full_raw, re.I)
        openssl = ssl_match_full.group(1).strip() if ssl_match_full else "OpenSSL: -"
        ssh_match_full = re.search(r'(OpenSSH.*)', full_raw, re.I)
        openssh = ssh_match_full.group(1).strip() if ssh_match_full else "OpenSSH: -"

    return {
        "version": version,
        "openssl": openssl,
        "openssh": openssh,
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

conn = get_connection()
cursor = conn.cursor()

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류: {e}")
                st.rerun()

    with st.expander("💀 관리자 메뉴"):
        with open(DB_FILE, "rb") as f:
            st.download_button("💾 DB 다운로드", f, "security_notes_archive.db", "application/x-sqlite3", use_container_width=True)
        
        uploaded_db = st.file_uploader("📂 DB 복원", type=["db"])
        if uploaded_db and st.button("⚠️ 덮어쓰기"):
            conn.close()
            with open(DB_FILE, "wb") as f: f.write(uploaded_db.getbuffer())
            st.rerun()

        if st.button("💣 초기화"):
            conn.close()
            if os.path.exists(DB_FILE): os.remove(DB_FILE)
            init_db()
            st.rerun()

        if not hist_df.empty:
            del_v = st.selectbox("삭제", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ AhnLab TG 릴리즈노트 V1.0")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='security-comp'>{openssl}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='security-comp'>{openssh}</div>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                display_text = p.strip()
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws): continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 결과가 없습니다.")
        else:
            st.warning("데이터 추출 실패")
        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    if res.empty: st.info("검색 결과 없음")
    else:
        for _, row in res.iterrows(): render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)
elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")

