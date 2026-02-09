import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.8", layout="wide")

st.markdown("""
    <style>
    .version-header { font-size: 24px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 15px; border-radius: 8px; border-left: 8px solid #1565C0; margin-bottom: 15px; }
    .report-box { padding: 20px; border: 1px solid #ddd; background-color: #ffffff; border-radius: 8px; margin-bottom: 25px; }
    .item-box { padding: 10px 14px; margin-bottom: 8px; border-left: 4px solid #90CAF9; background-color: #F5F5F5; font-size: 15px; line-height: 1.6; }
    .highlight { background-color: #FFF59D; color: black; font-weight: bold; padding: 2px 4px; border-radius: 4px; }
    .meta-label { color: #1565C0; font-weight: bold; font-size: 16px; border-bottom: 2px solid #BBDEFB; margin-bottom: 10px; display: inline-block; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 문장 복원 파싱 (v35.8 개선판) ---
def robust_clean_text(text):
    """
    깨진 텍스트, 괄호, 잘린 단어를 복원하는 초강력 세탁기
    """
    if not text: return ""
    
    # 1. 줄바꿈을 공백으로 변환
    text = text.replace('\n', ' ')
    
    # 2. 하이픈으로 잘린 영단어 복원 (Ex: dae- mon -> daemon)
    text = re.sub(r'([a-zA-Z])-\s+([a-zA-Z])', r'\1\2', text)
    
    # 3. 괄호 보정 (Ex: "( d" -> "(d", "( ." -> "(. ", " )" -> ")")
    text = re.sub(r'\(\s+', '(', text)       # 여는 괄호 뒤 공백 제거
    text = re.sub(r'\s+\)', ')', text)       # 닫는 괄호 앞 공백 제거
    text = re.sub(r'\(\s*\.', '(.', text)    # (. 버전번호 등 보정
    
    # 4. 숫자/영어 사이의 불필요한 공백 보정 (버전 번호 등)
    # Ex: . 4. 57 -> .4.57
    text = re.sub(r'\.\s+(\d)', r'.\1', text)

    # 5. 다중 공백 제거
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

def fix_split_words(line_str):
    """
    [Type] Cat * Desc 구조에서 잘못 삽입된 * 구분자를 감지하여 단어를 붙임
    Ex: System 펌웨 * 어 -> System 펌웨어
    Ex: Apa * che -> Apache
    """
    # 1. 영문이 * 를 사이에 두고 잘린 경우 (Apa * che -> Apache)
    # 주의: 카테고리 구분이 사라지지만, 'Apa'라는 카테고리는 의미가 없으므로 합치는 게 이득
    line_str = re.sub(r'([a-zA-Z])\s*\*\s*([a-zA-Z])', r'\1\2', line_str)
    
    # 2. 한글이 * 를 사이에 두고 잘린 경우 (펌웨 * 어 -> 펌웨어)
    line_str = re.sub(r'([가-힣])\s*\*\s*([가-힣])', r'\1\2', line_str)
    
    # 3. CA 인증서 오류 보정 (C * A -> CA)
    line_str = re.sub(r'(?i)\bC\s*\*\s*A\b', 'CA', line_str) # C * A -> CA
    line_str = re.sub(r'(?i)\bC\s*\(A\b', 'CA', line_str)     # C (A -> CA (괄호 오인식 보정)

    return line_str

def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        extracted_data = [] 
        
        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # [전략 개선] 표 추출 옵션 강화
            # intersection_x_tolerance: 옆 칸 글자가 침범하는 것을 방지 (기본값보다 낮게 설정 시도)
            strategies = [
                # 전략 1: 선이 명확한 경우
                {"vertical_strategy": "lines", "horizontal_strategy": "lines", "snap_tolerance": 5, "intersection_x_tolerance": 5},
                # 전략 2: 선이 없고 공백으로 구분된 경우 (텍스트 기반)
                {"vertical_strategy": "text", "horizontal_strategy": "text", "snap_tolerance": 8, "min_words_vertical": 2}
            ]
            
            for settings in strategies:
                tables = page.extract_tables(table_settings=settings)
                if not tables: continue

                last_type = ""
                last_cat = ""
                
                for table in tables:
                    for row in table:
                        # None 데이터 방어
                        cells = [str(c).strip() if c else "" for c in row]
                        
                        if not cells or len(cells) < 2: continue
                        # 헤더 스킵
                        if any(x in cells[0] for x in ["구분", "Type", "분류"]) or any(x in cells[1] for x in ["항목", "기능분류"]): continue

                        v_type = cells[0]
                        v_cat = cells[1] if len(cells) > 1 else ""
                        v_desc_raw = cells[2] if len(cells) > 2 else "" 
                        v_id = cells[3] if len(cells) > 3 else ""

                        # Forward Fill (이전 값 채우기)
                        if v_type: last_type = v_type
                        else: v_type = last_type
                        
                        if v_cat: last_cat = v_cat
                        else: v_cat = last_cat

                        target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'TASK', 'Feature', '기능']
                        
                        # 키워드가 타입에 있고, 내용이 존재할 때
                        if v_desc_raw and any(k in v_type for k in target_keywords):
                            
                            # 1. 불렛 기호 및 잡동사니 제거
                            cleaned_desc = re.sub(r'[•\-o]\s*', '', v_desc_raw)
                            
                            # 2. 문장 복원 (줄바꿈 제거 및 공백 정리)
                            final_desc = robust_clean_text(cleaned_desc)
                            
                            # 3. 카테고리 텍스트 정리
                            final_cat = robust_clean_text(v_cat)

                            # 4. 문자열 조립
                            cat_part = f" {final_cat}" if final_cat else ""
                            id_part = f" ({v_id})" if v_id and v_id.lower() not in ["none", "", "-"] else ""
                            
                            # 기본 형태 조립
                            raw_line = f"[{v_type}]{cat_part} * {final_desc}{id_part}"
                            
                            # 5. [핵심] 조립 후 "봉합 수술" (Apa * che -> Apache)
                            fixed_line = fix_split_words(raw_line)
                            
                            if fixed_line not in extracted_data:
                                extracted_data.append(fixed_line)
            
            # [보조 전략] 텍스트 라인 파싱 (표 인식 실패 시 백업)
            text_lines = p_text.split('\n')
            for l in text_lines:
                clean_l = robust_clean_text(l)
                if not clean_l: continue

                # 대괄호로 시작하는 패턴 감지 [개선] ...
                match_bracket = re.match(r'^[•\-]?\s*\[([^\]]+)\]\s*(.*)', clean_l)
                if match_bracket:
                    tag, body = match_bracket.group(1), match_bracket.group(2)
                    if any(kw in tag for kw in ['개선', '신규', '이슈', '수정', 'BUG']):
                        if '/' in tag:
                            t1, t2 = tag.split('/', 1)
                            formatted = f"[{t1}] {t2} * {body}"
                        else:
                            formatted = f"[{tag}] * {body}"
                        
                        # 중복 방지 후 추가
                        if formatted not in extracted_data:
                            extracted_data.append(formatted)

        # 메타데이터 (버전, OpenSSL 등 추출)
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[a-z]?)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": "\n\n".join(extracted_data),
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

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

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.8)")

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
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
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
